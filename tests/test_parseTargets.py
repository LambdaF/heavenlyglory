import pytest
from ..heavenlyglory import parseTargets


def test_localTargetFile():
    # test reducing to one ip from "localhost" ips in test file
    assert parseTargets("./targets/localOnly.txt") == set(["127.0.0.1"])


def test_noFile():
    with pytest.raises(FileNotFoundError):
        parseTargets(".1337")


def test_badTargetsFile():
    with pytest.raises(Exception):
        parseTargets("./targets/badTargets.txt")
