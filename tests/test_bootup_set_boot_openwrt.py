"""Unit tests for `bootup_set_boot_openwrt`'s synchronous-read rewrites.

PR 4b replaces two `ser.write(...); time.sleep(N); ser.read(in_waiting)` races
with deterministic `read_until_prompt` (printenv) and `read_until` (saveenv)
calls. These tests pin the predicate behavior on representative scripted
streams.
"""

import threading
import time
from unittest.mock import patch

import pytest

from extremeflash.ws import bootup_set_boot_openwrt

from .fakes import FakeSerial

# Realistic-shaped printenv response containing MODEL= line and the U-Boot
# prompt at the end. The prompt has no trailing newline (the very reason
# read_until_prompt exists).
_PRINTENV_RESPONSE_AP3825 = (
    b"some=other\r\n"
    b"bootcmd=run boot_openwrt\r\n"
    b"boot_openwrt=cp.b 0xEC000000 0x2000000 0x2000000;interrupts off;bootm start 0x2000000;"
    b"bootm loados;fdt resize;fdt boardsetup;fdt resize;fdt boardsetup;fdt chosen;"
    b"fdt resize;fdt chosen;bootm prep;bootm go;\r\n"
    b"MODEL=AP3825i\r\n"
    b"Boot (PRI)->"
)

_PRINTENV_RESPONSE_AP3710_NO_BOOT_OPENWRT = b"some=other\r\nMODEL=AP3710i\r\nBoot (PRI)->"


def test_returns_apmodel_for_ap3825_with_existing_correct_boot_openwrt():
    """Happy path on AP3825: existing boot_openwrt matches the registry value;
    function returns the model without touching saveenv."""
    fake = FakeSerial(scripted_chunks=[_PRINTENV_RESPONSE_AP3825], timeout=0.05)
    cancel = threading.Event()
    with patch.object(time, "sleep", lambda *_a, **_kw: None):
        model = bootup_set_boot_openwrt(fake, cancel, dryrun=True)
    assert model.name == "AP3825"


def test_saveenv_predicate_matches_writing_to_flash():
    """saveenv read_until matches 'Writing to Flash' on first sighting."""
    fake = FakeSerial(timeout=0.05)
    fake.inject(_PRINTENV_RESPONSE_AP3710_NO_BOOT_OPENWRT)

    def feed_saveenv_response_after_writes():
        # Wait for the function to issue setenv writes + the saveenv command,
        # then inject the success line.
        time.sleep(0.1)
        fake.inject(b"Saving Environment to Flash...\r\n")
        fake.inject(b"Erasing Flash...\r\n")
        fake.inject(b"Writing to Flash... done\r\n")
        fake.inject(b"OK\r\n")

    threading.Thread(target=feed_saveenv_response_after_writes, daemon=True).start()

    cancel = threading.Event()
    with patch.object(time, "sleep", lambda *_a, **_kw: None):
        model = bootup_set_boot_openwrt(fake, cancel, dryrun=False)
    assert model.name == "AP3710"


def test_saveenv_predicate_matches_writing_to_nand():
    """AP3825 with NAND flash: saveenv predicate must match 'Writing to NAND'.
    The pre-PR-4b code looked for either 'Writing to NAND' or 'Writing to
    redundant NAND' — the read_until predicates preserve both."""
    fake = FakeSerial(timeout=0.05)
    fake.inject(b"some=other\r\nMODEL=AP3825i\r\nBoot (PRI)->")

    def feed_saveenv_response():
        time.sleep(0.1)
        fake.inject(b"Saving Environment to NAND...\r\n")
        fake.inject(b"Writing to NAND... done\r\n")

    threading.Thread(target=feed_saveenv_response, daemon=True).start()

    cancel = threading.Event()
    with patch.object(time, "sleep", lambda *_a, **_kw: None):
        model = bootup_set_boot_openwrt(fake, cancel, dryrun=False)
    assert model.name == "AP3825"


def test_saveenv_timeout_preserves_runtime_error():
    """If no 'Writing to ...' marker arrives within the saveenv timeout, the
    pre-existing RuntimeError contract must be preserved."""
    fake = FakeSerial(timeout=0.05)
    fake.inject(_PRINTENV_RESPONSE_AP3710_NO_BOOT_OPENWRT)
    # Don't inject any saveenv response — the read_until call should time out.

    cancel = threading.Event()
    with patch.object(time, "sleep", lambda *_a, **_kw: None):
        with pytest.raises(RuntimeError, match="saveenv did not successfully"):
            bootup_set_boot_openwrt(fake, cancel, dryrun=False)
