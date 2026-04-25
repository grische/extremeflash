"""Serial-console read primitives: `read_until` (line-oriented) and
`read_until_prompt` (byte-level for no-newline patterns).

`read_until` replaces hand-rolled `while not cancel.is_set(): line =
readline_from_serial(ser); if "X" in line: …` loops with a single helper that
takes a mapping of named predicates and returns the first match (with the line
that matched). `read_until_prompt` covers the byte-level pattern where the
target string has no trailing newline (e.g. the U-Boot prompt) — a line-oriented
helper would block on `readline()` until the port timeout elapses, then return a
buffer that may or may not contain the prompt.

Cancel-check placement:
  `read_until` checks `cancel.is_set()` *between* each `readline()` cycle
  (before issuing the next blocking `readline()`). With the new 1 s port
  timeout (also landed in PR 4a), worst-case cancel-to-raise latency is
  one `readline()` cycle ≈ 1 s.

`readline()` retry semantics:
  Port-level timeouts return an empty `b""`. The helper does NOT treat an
  empty readline as a match failure — it loops until either a predicate
  matches, the explicit `timeout` argument elapses, or `cancel` fires.
"""

import logging
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Optional

import serial

from .exceptions import OperationCancelled


def _decode_with_fallback(b: bytes) -> str:
    """Match readline_from_serial's decoding behavior: ASCII with str-fallback for
    non-ASCII bytes that occasionally arrive from the Linux kernel after the
    16550 driver banner."""
    try:
        return b.decode("ascii")
    except UnicodeDecodeError:
        return str(b)


def _debug_serial(line: str) -> None:
    """Inline copy of helpers.debug_serial — kept here to avoid the helpers→
    serial_console→helpers import cycle. Identical to helpers.debug_serial."""
    logging.debug(line.rstrip())


def read_until(
    ser: serial.Serial,
    predicates: Mapping[str, Callable[[str], bool]],
    cancel: threading.Event,
    timeout: Optional[float] = None,
) -> tuple[str, str]:
    """Read decoded lines from `ser` until one predicate matches, cancel fires,
    or `timeout` (in seconds) elapses.

    Returns (predicate_key, full_line). Never returns a sentinel — every
    successful return carries a matched key + the line that matched.

    Raises:
      OperationCancelled: `cancel` was set before any predicate matched.
      TimeoutError: `timeout` elapsed before any predicate matched.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        if cancel.is_set():
            raise OperationCancelled("cancel set before any predicate matched")
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"read_until timed out after {timeout}s without matching any predicate")

        bytestring = ser.readline()
        if not bytestring:
            # Empty readline = port-timeout cycle elapsed with no data. Loop and
            # re-check cancel/deadline; do NOT treat as match failure.
            continue

        line = _decode_with_fallback(bytestring)
        _debug_serial(line)
        for key, predicate in predicates.items():
            if predicate(line):
                return key, line


def read_until_prompt(
    ser: serial.Serial,
    prompts: Sequence[str],
    cancel: threading.Event,
    timeout: Optional[float] = None,
) -> tuple[str, str]:
    """Read raw bytes from `ser`, decoding to ASCII (with the str-fallback used
    by `read_until`), accumulating into a buffer until any prompt string appears
    as a substring of the accumulated buffer, cancel fires, or `timeout` elapses.

    Returns (matched_prompt, accumulated_buffer). The buffer includes everything
    read up to and including the chunk that contained the prompt.

    BEHAVIOR CHANGE vs pre-PR-4b `bootup_login_verification`: the helper
    *accumulates* across multiple reads. The pre-existing inline code at
    helpers.py:110-131 was one-shot — it polled until `in_waiting > len(prompt)`
    then read exactly that chunk and either matched or raised `RuntimeError`.
    A device that emitted noise before the prompt would raise spuriously; the
    accumulating helper succeeds. This relaxation is deliberate (the one-shot
    behavior was a fragility, not a feature). Locked in by
    tests/test_read_until_prompt.py::test_split_across_reads_accumulates.

    Raises:
      OperationCancelled: `cancel` was set before any prompt matched.
      TimeoutError: `timeout` elapsed before any prompt matched.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    buffer = ""
    while True:
        if cancel.is_set():
            raise OperationCancelled("cancel set before any prompt matched")
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"read_until_prompt timed out after {timeout}s")

        # Use `in_waiting` to avoid the line-oriented blocking of readline()
        # — prompts have no trailing newline, so readline would only return at
        # the port-timeout deadline. Drain whatever's available; if nothing,
        # sleep briefly and re-check cancel/deadline.
        n = ser.in_waiting
        if n == 0:
            time.sleep(0.05)
            continue

        chunk = ser.read(n)
        if not chunk:
            time.sleep(0.05)
            continue
        decoded = _decode_with_fallback(chunk)
        _debug_serial(decoded)
        buffer += decoded
        for prompt in prompts:
            if prompt in buffer:
                return prompt, buffer


# ---------------------------------------------------------------------------
# Workflow helpers — absorbed from helpers.py during PR 6's dissolution.
# Kept in this module because they all drive the serial console and compose
# read_until / read_until_prompt.
# ---------------------------------------------------------------------------


def debug_serial(line: str) -> None:
    """Public alias for the module-internal `_debug_serial`. Identical behavior;
    kept under the original name so call sites that imported `debug_serial`
    from helpers.py keep working with a one-line import update."""
    _debug_serial(line)


def write_to_serial(ser: serial.Serial, text: bytes, sleep: float = 0) -> str:
    ser.write(text)
    if sleep > 0:
        time.sleep(sleep)

    return_string = ser.readline().decode("ascii")
    _debug_serial(return_string)
    return return_string


def readline_from_serial(ser: serial.Serial) -> str:
    bytestring = ser.readline()
    try:
        line = bytestring.decode("ascii")
    except UnicodeDecodeError:
        # We receive non-ascii/non-utf8 chars from the Linux kernel like 0xea or 0x90
        # after "Serial: 8250/16550 driver, 16 ports, IRQ sharing enabled"
        line = str(bytestring)
        line.replace(r"\n", "\n")

    _debug_serial(line)
    return line


def is_kernel_booting(line):
    if "## Booting kernel from FIT Image at" in line:  # with U-Boot v2009.x
        # https://github.com/u-boot/u-boot/blob/f20393c5e787b3776c179d20f82a86bda124d651/common/cmd_bootm.c#L897
        return True

    # TODO: check if this works! the original check above might be called different with newer version of U-Boot:
    if "## Loading kernel from FIT Image at" in line:  # with U-Boot v2013.07 and newer
        # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/boot/image-fit.c#L2079
        return True

    # TODO: improve this section. Mixing usages here.
    if "[    0.000000] Linux version " in line:
        # kernel is booting
        return True

    return False


def bootup_interrupt(ser: serial.Serial, cancel: threading.Event):
    """Watch for the U-Boot diag prompt and send `x` to enter the boot prompt.

    Kept its own shape (not a read_until call) because it accumulates an
    unflushed buffer and prints partial-line debug output as data arrives —
    a line-oriented helper would lose the partial-progress logging.
    """
    bootlog_buffer = ""

    while not cancel.is_set():
        time.sleep(0.01)
        if ser.in_waiting == 0:
            continue

        try:
            new_data = ser.read(ser.in_waiting).decode("ascii")
        except UnicodeDecodeError as e:
            logging.warning(f"Failed to decode serial data: {e}")
            new_data = str(ser.read(ser.in_waiting))
        bootlog_buffer += new_data

        # Only print full lines to debug output
        while "\n" in bootlog_buffer:
            line_end = bootlog_buffer.find("\n") + 1
            _debug_serial(bootlog_buffer[:line_end])
            bootlog_buffer = bootlog_buffer[line_end:]

        if "Hit 'd' for diagnostics" in bootlog_buffer:
            text = b"x"  # send interrupt key
            _debug_serial(bootlog_buffer)  # print remaining debug buffer
            logging.info(f"Sending interrupt key {text.decode()} to enter Boot prompt.")
            time.sleep(0.5)  # sleep 500ms
            ser.write(text)
            break


def bootup_login(ser: serial.Serial, cancel: threading.Event):
    # Loops until the password-prompt echo confirms login attempt landed. The
    # current code is unbounded (no deadline) — match that with timeout=None;
    # the user may have paused before powering the AP. Cancel responsiveness
    # is bounded by the serial port timeout (1 s after PR 4a's reduction).
    while True:
        key, _line = read_until(
            ser,
            predicates={
                "timeout_prompt": lambda line: "[30s timeout]" in line,
                "password_echo": lambda line: "password: new2day" in line,
            },
            cancel=cancel,
            timeout=None,
        )
        if key == "timeout_prompt":
            time.sleep(0.1)
            logging.info("Attempting to log in.")
            ser.write(b"admin\n")
            time.sleep(0.1)
            ser.write(b"new2day\n")
            continue
        # key == "password_echo"
        time.sleep(0.1)  # sleep 500ms
        logging.info("Checking if login was successful.")
        break


def bootup_login_verification(ser: serial.Serial, cancel: threading.Event):
    """Wait for the U-Boot prompt confirming login succeeded.

    Behavior change vs pre-PR-4b: this is now an *accumulating* substring match
    over the read buffer rather than a one-shot read-then-raise. A device that
    emits noise before the prompt now succeeds where it previously raised
    RuntimeError("U-Boot login failed :(("). The relaxation is deliberate (the
    one-shot behavior was a fragility, not a feature). See `read_until_prompt`'s
    docstring for the full rationale.

    Timeout: 30 s — login response should arrive within seconds; 30 s is generous
    headroom over real-world latency.
    """
    read_until_prompt(
        ser,
        prompts=["Boot (PRI)->", "Boot (BAK)->"],
        cancel=cancel,
        timeout=30,
    )
    logging.info("U-Boot login successful!")


def boot_wait_for_brlan(ser: serial.Serial, cancel: threading.Event):
    """Wait until the AP's br-lan bridge is ready to receive traffic.

    The "eth0: Link is Up" comes up, then goes down again and then comes up again
    after eth0 has entered promiscuous mode and the bridge has been created.

    Timeout: 180 s — 2x the observed worst-case kernel-to-br-lan time on the slowest
    supported model (AP3825).
    """
    read_until(
        ser,
        predicates={
            # OpenWRT 22.10 and earlier:
            "link_ready_22": lambda line: "br-lan: link becomes ready" in line,
            # OpenWRT 24.10 and later:
            "fwd_state_24": lambda line: "br-lan: port" in line and "entered forwarding state" in line,
        },
        cancel=cancel,
        timeout=180,
    )
    logging.info("br-lan is ready.")
    time.sleep(2)  # sometimes br-lan is ready but the default IP is still not reachable


def boot_set_ips(ser, new_ap_ip):
    logging.info(f"Setting new AP ip to {new_ap_ip}")
    ip_str = new_ap_ip.with_prefixlen.encode("ascii")

    write_to_serial(ser, b"\n")  # login
    write_to_serial(ser, b"ip address del 192.168.1.1 dev br-lan\n")  # remove default IP to avoid collisions
    write_to_serial(ser, b"ip address add " + ip_str + b" dev br-lan\n")
    write_to_serial(ser, b"ip -4 address show\n")
    time.sleep(0.5)


def keep_logging_until_reboot(ser: serial.Serial, cancel: threading.Event):
    """Watch for sysupgrade completion and the eventual reboot.

    Timeout: 300 s — covers full sysupgrade + reboot on AP3825 with NAND.
    `Upgrade completed` is logged on first sighting; the loop terminates only
    on `reboot: Restarting system`.
    """
    while True:
        key, _line = read_until(
            ser,
            predicates={
                "upgrade_done": lambda line: "Upgrade completed" in line,
                "rebooting": lambda line: "reboot: Restarting system" in line,
            },
            cancel=cancel,
            timeout=300,
        )
        if key == "upgrade_done":
            logging.info("Flashing successful.")
            continue
        # key == "rebooting"
        logging.info("Reboot detected. Stopping serial connection.")
        break
