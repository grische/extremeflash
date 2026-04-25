"""Test doubles for hardware/IO dependencies."""

import time
from collections import deque


class FakeSerial:
    """Subset of `serial.Serial` used by extremeflash's helpers, backed by a scripted byte stream.

    Byte semantics:
      - `write(b)` appends to `self.writes` (a list of bytes); never blocks.
      - `read(n)` drains up to n bytes from the head of the scripted-chunk queue. If the
         queue is empty and `self.timeout` is set, it sleeps `min(timeout, 0.05)` then returns b"".
      - `readline()` accumulates bytes from the queue until a `\\n` is seen, the queue is
         exhausted, or `self.timeout` elapses (real wall-clock).
      - `in_waiting` returns the count of bytes currently buffered.
      - `inject(b)` appends `b` to the queue mid-test (e.g., from another thread).
    """

    def __init__(self, scripted_chunks=None, timeout=None, name="/dev/fakeserial"):
        self._buffer = deque()
        if scripted_chunks:
            for chunk in scripted_chunks:
                self._buffer.append(chunk)
        self.timeout = timeout
        self.name = name
        self.writes: list[bytes] = []
        self._closed = False

    def write(self, b: bytes) -> int:
        self.writes.append(b)
        return len(b)

    def read(self, n: int) -> bytes:
        if not self._buffer:
            if self.timeout is not None:
                time.sleep(min(self.timeout, 0.05))
            return b""
        out = bytearray()
        while self._buffer and len(out) < n:
            chunk = self._buffer.popleft()
            take = min(len(chunk), n - len(out))
            out.extend(chunk[:take])
            if take < len(chunk):
                self._buffer.appendleft(chunk[take:])
        return bytes(out)

    def readline(self) -> bytes:
        deadline = None if self.timeout is None else time.monotonic() + self.timeout
        out = bytearray()
        while True:
            while self._buffer and self._buffer[0]:
                chunk = self._buffer.popleft()
                nl_idx = chunk.find(b"\n")
                if nl_idx >= 0:
                    out.extend(chunk[: nl_idx + 1])
                    if nl_idx + 1 < len(chunk):
                        self._buffer.appendleft(chunk[nl_idx + 1 :])
                    return bytes(out)
                out.extend(chunk)
            if deadline is None:
                return bytes(out)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return bytes(out)
            time.sleep(min(remaining, 0.01))

    @property
    def in_waiting(self) -> int:
        return sum(len(c) for c in self._buffer)

    def inject(self, b: bytes) -> None:
        self._buffer.append(b)

    def close(self) -> None:
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
