"""Byte-stream-equivalence tests for `boot_via_tftp` against the pre-PR-2 golden snapshots.

For AP3710/AP3825/AP3935 the fixtures under `tests/fixtures/` were captured from
the pre-PR-2 code via `tests/_capture_golden.py`. AP3715 was omitted from the
capture (pre-PR-2 `boot_via_tftp` raised RuntimeError on `model="AP3715"`); its
expected byte stream is asserted directly here so the latent bug is fixed by
this PR.
"""

import ipaddress
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from extremeflash.models import SUPPORTED_MODELS
from extremeflash.ws import boot_via_tftp

from .fakes import FakeSerial

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _drive_boot_via_tftp(model_name: str) -> bytes:
    fake = FakeSerial(timeout=0.01)
    placeholder = b"\r\n"
    for _ in range(5):
        fake.inject(placeholder)
    fake.inject(b"Bytes transferred = 6291456 (600000 hex)\r\n")
    for _ in range(20):
        fake.inject(placeholder)
    tftp_ip = ipaddress.ip_interface("192.168.1.70/24")
    new_ap_ip = ipaddress.ip_interface("192.168.1.254/24")
    model = next(m for m in SUPPORTED_MODELS if m.name == model_name)
    cancel = threading.Event()  # never set; loop terminates on "Bytes transferred"
    with patch.object(time, "sleep", lambda *_args, **_kwargs: None):
        boot_via_tftp(fake, tftp_ip, "openwrt-initramfs.bin", new_ap_ip, model, cancel)
    return b"".join(fake.writes)


@pytest.mark.parametrize("model_name", ["AP3710", "AP3825", "AP3935"])
def test_byte_sequence_matches_golden(model_name):
    expected = (FIXTURES_DIR / f"boot_via_tftp_{model_name}.bytes").read_bytes()
    actual = _drive_boot_via_tftp(model_name)
    assert actual == expected, f"byte stream regression for {model_name}"


def test_ap3715_byte_sequence():
    """Pre-PR-2 raised on AP3715. Asserts the new (working) byte stream directly."""
    actual = _drive_boot_via_tftp("AP3715")
    expected = (
        b"setenv ipaddr 192.168.1.254\n"
        b"setenv netmask 255.255.255.0\n"
        b"setenv serverip 192.168.1.70\n"
        b"setenv gatewayip 192.168.1.70\n"
        b"tftpboot 0x2000000 192.168.1.70:openwrt-initramfs.bin\n"
        b"bootm\n"
    )
    assert actual == expected
