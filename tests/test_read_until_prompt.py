"""Unit tests for `read_until_prompt` (byte-level no-newline match)."""

import threading
import time

import pytest

from extremeflash.exceptions import OperationCancelled
from extremeflash.serial_console import read_until_prompt

from .fakes import FakeSerial


def test_single_read_prompt_in_buffer():
    """Happy path: prompt arrives in one chunk (no preceding noise)."""
    fake = FakeSerial(scripted_chunks=[b"Boot (PRI)->"], timeout=0.05)
    cancel = threading.Event()
    matched, buffer = read_until_prompt(
        fake,
        prompts=["Boot (PRI)->", "Boot (BAK)->"],
        cancel=cancel,
        timeout=2.0,
    )
    assert matched == "Boot (PRI)->"
    assert "Boot (PRI)->" in buffer


def test_split_across_reads_accumulates():
    """LOAD-BEARING test: locks in the deliberate behavior change vs pre-PR-4b
    bootup_login_verification. A noisy preamble in one read followed by the
    prompt in a later chunk MUST match successfully via accumulation.

    Pre-PR-4b code raised RuntimeError on the first non-matching chunk;
    this helper accumulates and succeeds.
    """
    fake = FakeSerial(timeout=0.05)
    fake.inject(b"some noise from the device\r\n")

    cancel = threading.Event()

    def inject_prompt_after_delay():
        time.sleep(0.1)
        fake.inject(b"more noise\r\nBoot (PRI)->")

    threading.Thread(target=inject_prompt_after_delay, daemon=True).start()

    matched, buffer = read_until_prompt(
        fake,
        prompts=["Boot (PRI)->", "Boot (BAK)->"],
        cancel=cancel,
        timeout=2.0,
    )
    assert matched == "Boot (PRI)->"
    assert "some noise" in buffer  # earlier noise preserved in accumulated buffer
    assert "Boot (PRI)->" in buffer


def test_backup_prompt_matches():
    """Either prompt in the `prompts` Sequence may match."""
    fake = FakeSerial(scripted_chunks=[b"some preamble\r\nBoot (BAK)->"], timeout=0.05)
    cancel = threading.Event()
    matched, _buffer = read_until_prompt(
        fake,
        prompts=["Boot (PRI)->", "Boot (BAK)->"],
        cancel=cancel,
        timeout=2.0,
    )
    assert matched == "Boot (BAK)->"


def test_cancel_raises_operation_cancelled():
    fake = FakeSerial(timeout=0.05)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(OperationCancelled):
        read_until_prompt(fake, prompts=["never"], cancel=cancel, timeout=None)


def test_timeout_raises_timeout_error():
    fake = FakeSerial(timeout=0.05)
    cancel = threading.Event()
    with pytest.raises(TimeoutError, match="0.2"):
        read_until_prompt(fake, prompts=["never"], cancel=cancel, timeout=0.2)


def test_non_ascii_bytes_fall_back():
    """Non-ASCII bytes in the buffer don't crash the read; ASCII prompt still matches."""
    fake = FakeSerial(scripted_chunks=[b"\xea\x90 garbage \r\nBoot (PRI)->"], timeout=0.05)
    cancel = threading.Event()
    matched, _buffer = read_until_prompt(
        fake,
        prompts=["Boot (PRI)->"],
        cancel=cancel,
        timeout=2.0,
    )
    assert matched == "Boot (PRI)->"
