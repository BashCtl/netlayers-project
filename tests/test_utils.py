import pytest

from netlayers.untils import format_ip, format_mac


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


def test_format_valid_ip_bytes_to_string():
    assert format_ip(b"\xc0\xa8\x01\x01") == "192.168.1.1"


def test_format_zero_padded_ip_bytes():
    assert format_ip(b"\x00\x00\x00\x00") == "0.0.0.0"


def test_format_ivalid_ip_bytes_length_raises_error():
    with pytest.raises(ValueError, match="An IP address must be exactly 4 bytes"):
        format_ip(b"\xff" * 5)


def test_format_empty_ip_bytes_raises_error():
    with pytest.raises(ValueError, match="An IP address must be exactly 4 bytes"):
        format_ip(b"")
