"""Serial-console read primitives: `read_until` (line-oriented).

This module replaces a handful of hand-rolled `while not cancel.is_set(): line =
readline_from_serial(ser); if "X" in line: …` loops with a single helper that
takes a mapping of named predicates and returns the first match (with the line
that matched). PR 4b adds a sibling `read_until_prompt` for byte-level matches
where the line-oriented form is unsuitable (e.g. the U-Boot prompt has no
trailing newline).

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
from collections.abc import Callable, Mapping
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
