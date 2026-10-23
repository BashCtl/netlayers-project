import pytest

from netlayers.untils import format_mac


def test_format_mac_basic():
    assert format_mac(b"\xaa\xbb\xcc\x11\x22\x33") == "aa:bb:cc:11:22:33"


def test_format_mac_zero_padding():
    assert format_mac(b"\x00\x01\x02\x03\x04\x05") == "00:01:02:03:04:05"


def test_format_mac_broadcast():
    assert format_mac(b"\xff" * 6) == "ff:ff:ff:ff:ff:ff"


def test_format_invalid_length_byte_mac_raises_error():
    with pytest.raises(ValueError, match="A MAC address must be exactly 6 bytes"):
        format_mac(b"\xff" * 7)


def test_format_empty_byte_mac_raises_error():
    with pytest.raises(ValueError, match="A MAC address must be exactly 6 bytes"):
        format_mac(b"")
