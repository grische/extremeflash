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
