import pytest
from ..heavenlyglory import expandRange


def test_goodSingleIP():
    assert expandRange("127.0.0.1") == ["127.0.0.1"]


def test_goodRange():
    assert expandRange("127.0.0.0/31") == ["127.0.0.0", "127.0.0.1"]
    assert expandRange("127.0.0.0/30") == ["127.0.0.0",
                                           "127.0.0.1",
                                           "127.0.0.2",
                                           "127.0.0.3"]


def test_badRange():
    with pytest.raises(Exception):
        expandRange("127.0.0.0/48")


def test_hostname():
    assert expandRange("localhost") == ["localhost"]


def test_empty():
    with pytest.raises(Exception):
        expandRange("")
