"""Unit tests for U-Boot `printenv`-based model detection.

Test file uses a neutral name so it survives the PR 2 rename
(`get_model_name_from_printenv` -> `get_model_from_printenv`).
"""

import pytest

from extremeflash.ws import get_model_name_from_printenv


def _printenv(model_name: str) -> str:
    return f"some=other\r\nMODEL={model_name}\r\nfoo=bar\r\n"


@pytest.mark.parametrize(
    "model_name,expected",
    [
        ("AP3710i", "AP3710"),
        ("AP3715i", "AP3715"),
        ("AP3825i", "AP3825"),
        ("AP3935i", "AP3935"),
        ("AP3935i-FCC", "AP3935"),
        ("AP3935i-IL", "AP3935"),
        ("AP3935i-ROW", "AP3935"),
    ],
)
def test_recognizes_supported_models(model_name, expected):
    assert get_model_name_from_printenv(_printenv(model_name)) == expected


def test_missing_model_raises():
    with pytest.raises(RuntimeWarning, match="no MODEL name"):
        get_model_name_from_printenv("foo=bar\r\nbaz=qux\r\n")


def test_unknown_model_raises():
    with pytest.raises(RuntimeWarning, match="Unexpected Model"):
        get_model_name_from_printenv(_printenv("AP9999z"))
