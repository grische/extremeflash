"""Unit tests for the ApModel registry.

Asserts the per-model byte sequences and timing values match what the
pre-PR-2 if/elif chains in ws.py emitted.
"""

import pytest

from extremeflash.models import SUPPORTED_MODELS, ApModel


def _by_name(name: str) -> ApModel:
    for m in SUPPORTED_MODELS:
        if m.name == name:
            return m
    raise KeyError(name)


def test_registry_has_four_models():
    names = [m.name for m in SUPPORTED_MODELS]
    assert names == ["AP3710", "AP3715", "AP3825", "AP3935"]


def test_model_names_are_prefix_disjoint():
    """Detection relies on `startswith` matching; no name may be a prefix of another."""
    names = [m.name for m in SUPPORTED_MODELS]
    for a in names:
        for b in names:
            if a != b:
                assert not a.startswith(b), f"{a!r} starts with {b!r}: prefix-disjoint invariant broken"


def test_ap3710_boot_openwrt_params():
    assert _by_name("AP3710").boot_openwrt_params == (
        b"setenv bootargs; cp.b 0xee000000 0x1000000 0x1000000; bootm 0x1000000"
    )


def test_ap3715_boot_openwrt_params():
    assert _by_name("AP3715").boot_openwrt_params == (
        b"sf probe 0;sf read 0x2000000 0x140000 0x1000000;bootm 0x2000000;"
    )


def test_ap3825_boot_openwrt_params():
    assert _by_name("AP3825").boot_openwrt_params == (
        b"cp.b 0xEC000000 0x2000000 0x2000000;"
        b"interrupts off;"
        b"bootm start 0x2000000;"
        b"bootm loados;"
        b"fdt resize;"
        b"fdt boardsetup;"
        b"fdt resize;"
        b"fdt boardsetup;"
        b"fdt chosen;"
        b"fdt resize;"
        b"fdt chosen;"
        b"bootm prep;"
        b"bootm go;"
    )


def test_ap3935_boot_openwrt_params():
    assert _by_name("AP3935").boot_openwrt_params == (
        b"sf probe 0; sf read 0x41500000 0x003c0000 0x00e10000; bootm 0x41500000"
    )


@pytest.mark.parametrize(
    "name,expected_address",
    [
        ("AP3710", b"0x1000000"),
        ("AP3715", b"0x2000000"),  # PR 2 fix: pre-PR-2 omitted AP3715 entirely
        ("AP3825", b"0x2000000"),
        ("AP3935", b"0x42000000"),
    ],
)
def test_tftp_load_addresses(name, expected_address):
    assert _by_name(name).tftp_load_address == expected_address


def test_ap3710_bootm_sequence():
    assert _by_name("AP3710").bootm_sequence == ((b"bootm\n", 0.1),)


def test_ap3715_bootm_sequence():
    assert _by_name("AP3715").bootm_sequence == ((b"bootm\n", 0.1),)


def test_ap3825_bootm_sequence():
    assert _by_name("AP3825").bootm_sequence == (
        (b"interrupts off\n", 0),
        (b"bootm start 0x2000000\n", 0.2),
        (b"bootm loados\n", 2),
        (b"fdt resize\n", 0.1),
        (b"fdt boardsetup\n", 0.1),
        (b"fdt chosen\n", 0.1),
        (b"bootm prep\n", 0.1),
        (b"bootm go\n", 0.1),
    )


def test_ap3935_bootm_sequence():
    assert _by_name("AP3935").bootm_sequence == (
        (b"bootm start 0x42000000\n", 0.2),
        (b"bootm loados\n", 2),
        (b"bootm prep\n", 0.1),
        (b"bootm go\n", 0.1),
    )


@pytest.mark.parametrize(
    "name,expected_seconds",
    [
        ("AP3710", 2.0),
        ("AP3715", 6.0),  # SPI flash on AP3715 is considerably slower
        ("AP3825", 2.0),
        ("AP3935", 2.0),
    ],
)
def test_saveenv_wait_seconds(name, expected_seconds):
    assert _by_name(name).saveenv_wait_seconds == expected_seconds
