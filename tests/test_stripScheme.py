import pytest
from ..heavenlyglory import stripScheme


def test_goodValue():
    assert stripScheme("https://google.com") == "google.com"


def test_badValue():
    assert stripScheme("asdf") == "asdf"


def test_goodIPValue():
    assert stripScheme("https://127.0.0.1") == "127.0.0.1"


def test_badIPValue():
    assert stripScheme("https://0.0.0.1") == "0.0.0.1"


def test_badEmptyValue():
    assert stripScheme("") == ""


def test_except():
    with pytest.raises(Exception):
        stripScheme(123)
