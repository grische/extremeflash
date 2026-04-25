"""Unit tests for `read_until` (line-oriented serial read primitive)."""

import threading
import time

import pytest

from extremeflash.exceptions import OperationCancelled
from extremeflash.serial_console import read_until

from .fakes import FakeSerial


def test_first_matching_predicate_wins():
    """Returns (key, full_line) on first matched predicate. Order of predicates
    is iteration order of the mapping; the test deliberately puts a 'never'
    predicate first to confirm key selection by *match*, not by order."""
    fake = FakeSerial(scripted_chunks=[b"unrelated\n", b"target line here\n"], timeout=0.05)
    cancel = threading.Event()
    key, line = read_until(
        fake,
        predicates={
            "never": lambda line: False,
            "target": lambda line: "target" in line,
        },
        cancel=cancel,
        timeout=2.0,
    )
    assert key == "target"
    assert line == "target line here\n"


def test_cancel_raises_operation_cancelled():
    """cancel set mid-stream → OperationCancelled within ≤ port-timeout."""
    fake = FakeSerial(scripted_chunks=[], timeout=0.05)
    cancel = threading.Event()
    cancel.set()  # immediate cancel
    with pytest.raises(OperationCancelled):
        read_until(
            fake,
            predicates={"never": lambda line: False},
            cancel=cancel,
            timeout=None,
        )


def test_timeout_raises_timeout_error():
    """Explicit timeout argument elapses → TimeoutError."""
    fake = FakeSerial(scripted_chunks=[], timeout=0.05)
    cancel = threading.Event()
    start = time.monotonic()
    with pytest.raises(TimeoutError, match="0.2"):
        read_until(
            fake,
            predicates={"never": lambda line: False},
            cancel=cancel,
            timeout=0.2,
        )
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, "should not exceed timeout by much"


def test_non_ascii_bytes_fall_back_via_str():
    """Non-ASCII bytes (occasionally arrive after the 16550 driver banner) must
    be tolerated via the str-fallback decoding, not crash the read."""
    fake = FakeSerial(scripted_chunks=[b"\xea\x90\xff bad bytes\n", b"target\n"], timeout=0.05)
    cancel = threading.Event()
    # First line contains "bad bytes" but isn't `target`; second matches.
    key, line = read_until(
        fake,
        predicates={"target": lambda line: "target" in line},
        cancel=cancel,
        timeout=2.0,
    )
    assert key == "target"


def test_retries_past_port_timeouts():
    """Port timeout (FakeSerial returns b"" after 0.05 s of no data) must NOT
    cause read_until to bail. The helper loops until either a predicate matches,
    the explicit `timeout` argument elapses, or cancel fires.

    This locks in the behavior that read_until's deadline is its explicit
    `timeout` argument — not the underlying serial port timeout.
    """
    fake = FakeSerial(scripted_chunks=[], timeout=0.05)
    cancel = threading.Event()

    def inject_after_delay():
        # Simulate data arriving after several port-timeout cycles.
        time.sleep(0.2)
        fake.inject(b"target line\n")

    threading.Thread(target=inject_after_delay, daemon=True).start()

    key, line = read_until(
        fake,
        predicates={"target": lambda line: "target" in line},
        cancel=cancel,
        timeout=2.0,
    )
    assert key == "target"


def test_cancel_check_ordering_across_port_timeouts():
    """Cancel must raise within ≤ one port-timeout cycle of being set, even
    if no predicate has matched yet. Locks in the 'check cancel between each
    readline cycle' rule."""
    fake = FakeSerial(scripted_chunks=[], timeout=0.05)
    cancel = threading.Event()

    def cancel_after_delay():
        time.sleep(0.1)  # ~2 port-timeout cycles
        cancel.set()

    threading.Thread(target=cancel_after_delay, daemon=True).start()

    start = time.monotonic()
    with pytest.raises(OperationCancelled):
        read_until(
            fake,
            predicates={"never": lambda line: False},
            cancel=cancel,
            timeout=None,
        )
    elapsed = time.monotonic() - start
    # Cancel set at ~0.1 s; should raise within one port-timeout cycle (~0.05 s)
    # so total ≤ ~0.2 s. Headroom allows for scheduling jitter on slow CI.
    assert elapsed < 0.5, f"cancel-to-raise latency {elapsed:.3f}s exceeded threshold"
