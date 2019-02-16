import pytest
from ..heavenlyglory import hostnameToIP


def test_goodHostValue():
    assert hostnameToIP("localhost") == "127.0.0.1"


def test_badValue():
    assert hostnameToIP("") == "0.0.0.0"


def test_goodIPValue():
    assert hostnameToIP("127.0.0.1") == "127.0.0.1"


def test_badIPValue():
    assert hostnameToIP("127.0.0.0/24") == "127.0.0.0/24"


def test_except():
    with pytest.raises(Exception):
        hostnameToIP(123)
