"""Unit tests for U-Boot `printenv`-based model detection."""

import pytest

from extremeflash.models import get_model_from_printenv


def _printenv(model_name: str) -> str:
    return f"some=other\r\nMODEL={model_name}\r\nfoo=bar\r\n"


@pytest.mark.parametrize(
    "model_name,expected_name",
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
def test_recognizes_supported_models(model_name, expected_name):
    assert get_model_from_printenv(_printenv(model_name)).name == expected_name


def test_missing_model_raises():
    with pytest.raises(RuntimeWarning, match="no MODEL name"):
        get_model_from_printenv("foo=bar\r\nbaz=qux\r\n")


def test_unknown_model_raises():
    with pytest.raises(RuntimeWarning, match="Unexpected Model"):
        get_model_from_printenv(_printenv("AP9999z"))
