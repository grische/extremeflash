"""One-shot script that captures golden byte sequences from `boot_via_tftp` for each
supported model.

Originally captured against the pre-PR-2 code; PR 2 retargeted the import paths so
the script keeps working after the `ApModel` refactor (a re-run produces identical
fixtures, providing a useful integration check). The captured bytes are pinned by
`tests/test_boot_via_tftp.py` as the no-behavioral-change guarantee.

Run from repo root with `poetry run python -m tests._capture_golden`. Writes one
fixture file per supported model into `tests/fixtures/boot_via_tftp_<model>.bytes`.
The leading underscore keeps pytest from auto-collecting the file.

NOTE: AP3715 is intentionally skipped — pre-PR-2 `boot_via_tftp` raised
RuntimeError on `model="AP3715"` (the TFTP-load-address dispatch was missing).
PR 2 fixes that latent bug; the new AP3715 sequence is asserted directly in
`tests/test_boot_via_tftp.py` rather than against a captured fixture.
"""

import ipaddress
import time
from pathlib import Path
from unittest.mock import patch

from extremeflash.helpers import event_keep_serial_active
from extremeflash.models import SUPPORTED_MODELS, ApModel
from extremeflash.ws import boot_via_tftp

from .fakes import FakeSerial


def capture_for_model(model: ApModel) -> bytes:
    # boot_via_tftp issues several `write_to_serial` calls before the TFTP-watch
    # loop, each of which calls `ser.readline()` to log the device's echo. Those
    # readlines consume from the same scripted queue, so we provide a generous
    # supply of placeholder lines and place the "Bytes transferred" marker after
    # the 5 setenv/tftpboot writes that precede the wait loop.
    fake = FakeSerial(timeout=0.01)
    placeholder = b"\r\n"
    for _ in range(5):
        fake.inject(placeholder)
    fake.inject(b"Bytes transferred = 6291456 (600000 hex)\r\n")
    for _ in range(20):  # generous tail for any post-wait readlines
        fake.inject(placeholder)
    tftp_ip = ipaddress.ip_interface("192.168.1.70/24")
    new_ap_ip = ipaddress.ip_interface("192.168.1.254/24")
    event_keep_serial_active.set()
    try:
        # Skip real-world sleeps to keep capture fast.
        with patch.object(time, "sleep", lambda *_args, **_kwargs: None):
            boot_via_tftp(fake, tftp_ip, "openwrt-initramfs.bin", new_ap_ip, model)
    finally:
        event_keep_serial_active.clear()
    return b"".join(fake.writes)


def main() -> None:
    out_dir = Path(__file__).parent / "fixtures"
    out_dir.mkdir(exist_ok=True)
    for model in SUPPORTED_MODELS:
        if model.name == "AP3715":
            print(f"skipping {model.name} (pre-PR-2 raised; new sequence pinned in test directly)")
            continue
        bytes_out = capture_for_model(model)
        target = out_dir / f"boot_via_tftp_{model.name}.bytes"
        target.write_bytes(bytes_out)
        print(f"wrote {target} ({len(bytes_out)} bytes)")


if __name__ == "__main__":
    main()
