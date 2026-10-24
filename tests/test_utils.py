import pytest

from netlayers.untils import format_ip, format_mac, hexdump


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


def test_hexdump_empty_bytes():
    assert hexdump(b"") == ""


def test_hexdump_one_printable_char():
    assert (
        hexdump(b"A")
        == "00000000  41                                               |A|"
    )


def test_hexdump_printable_text():
    assert (
        hexdump(b"Hello")
        == "00000000  48 65 6c 6c 6f                                   |Hello|"
    )


def test_hexdump_printable_and_not_printable_bytes():
    assert (
        hexdump(b"\x00\x01\x41\x42\x7f")
        == "00000000  00 01 41 42 7f                                   |..AB.|"
    )


def test_hexdump_exactly_8_bytes():
    assert hexdump(b"\x45\x00\x00\x54\x1c\x46\x40\x00") == "00000000  45 00 00 54 1c 46 40 00                          |E..T.F@.|"


def test_hexdump_exactly_16_bytes():
    assert hexdump(b"0123456789ABCDEF") == "00000000  30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46  |0123456789ABCDEF|"

def test_hexdump_more_than_16_bytes():
    assert hexdump(b"ABCDEFGHIJKLMNOPQ") == """00000000  41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|
00000010  51                                               |Q|"""

def test_hexdump_all_non_printable_bytes():
    assert hexdump(b"\x00\x01\x02\x03\x1b\x7f\x80\xff") == "00000000  00 01 02 03 1b 7f 80 ff                          |........|"