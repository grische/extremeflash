"""Unit tests for `is_kernel_booting`."""

import pytest

from extremeflash.helpers import is_kernel_booting


@pytest.mark.parametrize(
    "line",
    [
        "## Booting kernel from FIT Image at 0x01000000\r\n",
        "## Loading kernel from FIT Image at 0x42000000 ...\r\n",
        "[    0.000000] Linux version 5.15.137 (builder@buildhost) ...\r\n",
    ],
)
def test_recognizes_booting_marker(line):
    assert is_kernel_booting(line) is True


@pytest.mark.parametrize(
    "line",
    [
        "",
        "Booting from network ...\r\n",
        "## Booting from FIT Image at 0x01000000\r\n",  # missing "kernel"
        "Linux version 5.15.137 (no leading kernel-time)\r\n",
        "br-lan: link becomes ready\r\n",
    ],
)
def test_does_not_match_unrelated_lines(line):
    assert is_kernel_booting(line) is False
