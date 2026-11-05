import ipaddress
import struct

import pytest

from netlayers.utils import (
    build_pseudo_header,
    format_ip,
    format_mac,
    hexdump,
    parse_ip,
    parse_mac,
    validate_uint,
)


@pytest.fixture
def pseudo_header_values():
    return {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "protocol": 6,
        "length": 100,
    }


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
    assert (
        hexdump(b"\x45\x00\x00\x54\x1c\x46\x40\x00")
        == "00000000  45 00 00 54 1c 46 40 00                          |E..T.F@.|"
    )


def test_hexdump_exactly_16_bytes():
    assert (
        hexdump(b"0123456789ABCDEF")
        == "00000000  30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46  |0123456789ABCDEF|"
    )


def test_hexdump_more_than_16_bytes():
    assert (
        hexdump(b"ABCDEFGHIJKLMNOPQ")
        == """00000000  41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|
00000010  51                                               |Q|"""
    )


def test_hexdump_all_non_printable_bytes():
    assert (
        hexdump(b"\x00\x01\x02\x03\x1b\x7f\x80\xff")
        == "00000000  00 01 02 03 1b 7f 80 ff                          |........|"
    )


@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        ("00:11:22:33:44:55", bytes.fromhex("001122334455")),
        ("aa:bb:cc:dd:ee:ff", bytes.fromhex("aabbccddeeff")),
        ("AA:BB:CC:DD:EE:FF", bytes.fromhex("AABBCCDDEEFF")),
        ("aA:bB:cC:dD:eE:fF", bytes.fromhex("aabbccddeeff")),
        ("00:00:00:00:00:00", b"\x00\x00\x00\x00\x00\x00"),
        ("FF:FF:FF:FF:FF:FF", b"\xff\xff\xff\xff\xff\xff"),
    ],
)
def test_parse_mac_valid(mac, expected):
    assert parse_mac(mac) == expected


@pytest.mark.parametrize(
    "mac",
    [
        "",
        "00:11:22:33:44",  # Too few octets
        "00:11:22:33:44:55:66",  # Too many octets
        "00-11-22-33-44-55",  # Wrong separator
        "0011:2233:4455",  # Wrong format
        "0:11:22:33:44:55",  # First octet too short
        "00:1:22:33:44:55",  # Octet too short
        "00:11:22:33:44:5",  # Last octet too short
        "000:11:22:33:44:55",  # Octet too long
        "gg:11:22:33:44:55",  # Invalid hex character
        "00:11:22:33:44:5g",  # Invalid hex character
        "00:11:22:33:44:5!",  # Special character
        "00:11:22:33:44:55\n",  # Trailing newline
        " 00:11:22:33:44:55",  # Leading whitespace
        "00:11:22:33:44:55 ",  # Trailing whitespace
    ],
)
def test_parse_mac_invalid(mac):
    with pytest.raises(ValueError, match="Invalid MAC address"):
        parse_mac(mac)


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("192.168.1.1", b"\xc0\xa8\x01\x01"),
        ("10.0.0.1", b"\x0a\x00\x00\x01"),
        ("127.0.0.1", b"\x7f\x00\x00\x01"),
        ("255.255.255.255", b"\xff\xff\xff\xff"),
        ("0.0.0.0", b"\x00\x00\x00\x00"),
    ],
)
def test_parse_ip_valid(ip, expected):
    result = parse_ip(ip)

    assert isinstance(result, bytes)
    assert len(result) == 4
    assert result == expected


def test_parse_ip_returns_ipv4_packed_bytes():
    ip = "192.168.1.10"

    result = parse_ip(ip)

    assert result == ipaddress.IPv4Address(ip).packed


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.168.1.1",
        "192.168.1.256",
        "192.168.1",
        "192.168.1.1.1",
        "not_an_ip",
        "",
        "2001:db8::1",
        "abc.def.ghi.jkl",
        "192.168.-1.1",
    ],
)
def test_parse_ip_invalid(invalid_ip):
    with pytest.raises(ipaddress.AddressValueError):
        parse_ip(invalid_ip)


def test_parse_ip_returns_four_bytes():
    result = parse_ip("8.8.8.8")

    assert len(result) == 4


def test_build_pseudo_header_returns_bytes(pseudo_header_values):
    result = build_pseudo_header(**pseudo_header_values)

    assert isinstance(result, bytes)


def test_build_pseudo_header_length(pseudo_header_values):
    result = build_pseudo_header(**pseudo_header_values)

    # 4 bytes source IP
    # 4 bytes destination IP
    # 2 bytes protocol
    # 2 bytes length
    assert len(result) == 12


def test_build_pseudo_header_source_ip(pseudo_header_values):
    result = build_pseudo_header(**pseudo_header_values)

    assert result[:4] == bytes.fromhex("C0A8010A")


def test_build_pseudo_header_destination_ip(pseudo_header_values):
    result = build_pseudo_header(**pseudo_header_values)

    assert result[4:8] == bytes.fromhex("C0A80114")


def test_build_pseudo_header_protocol(pseudo_header_values):
    result = build_pseudo_header(**pseudo_header_values)

    assert result[8:10] == struct.pack("!H", 6)


def test_build_pseudo_header_length_field(pseudo_header_values):
    result = build_pseudo_header(**pseudo_header_values)

    assert result[10:12] == struct.pack("!H", 100)


def test_build_pseudo_header_complete_structure(pseudo_header_values):
    result = build_pseudo_header(**pseudo_header_values)

    src_ip, dst_ip, protocol, length = struct.unpack(
        "!4s4sHH",
        result,
    )

    assert src_ip == ipaddress.IPv4Address("192.168.1.10").packed

    assert dst_ip == ipaddress.IPv4Address("192.168.1.20").packed

    assert protocol == 6
    assert length == 100


@pytest.mark.parametrize(
    "protocol",
    [-1, 256, 1000],
)
def test_build_pseudo_header_invalid_protocol(
    pseudo_header_values,
    protocol,
):
    pseudo_header_values["protocol"] = protocol

    with pytest.raises(
        ValueError,
        match="Protocol out of range",
    ):
        build_pseudo_header(**pseudo_header_values)


@pytest.mark.parametrize(
    "protocol",
    [0, 1, 6, 17, 255],
)
def test_build_pseudo_header_valid_protocol(
    pseudo_header_values,
    protocol,
):
    pseudo_header_values["protocol"] = protocol

    result = build_pseudo_header(**pseudo_header_values)

    assert struct.unpack("!H", result[8:10])[0] == protocol


@pytest.mark.parametrize(
    "length",
    [-1, 65536, 100000],
)
def test_build_pseudo_header_invalid_length(
    pseudo_header_values,
    length,
):
    pseudo_header_values["length"] = length

    with pytest.raises(
        ValueError,
        match="Length out of range",
    ):
        build_pseudo_header(**pseudo_header_values)


@pytest.mark.parametrize(
    "length",
    [0, 1, 1500, 65535],
)
def test_build_pseudo_header_valid_length(
    pseudo_header_values,
    length,
):
    pseudo_header_values["length"] = length

    result = build_pseudo_header(**pseudo_header_values)

    assert struct.unpack("!H", result[10:12])[0] == length


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.168.1.1",
        "192.168.1",
        "not_an_ip",
        "",
        "2001:db8::1",
    ],
)
def test_build_pseudo_header_invalid_source_ip(
    pseudo_header_values,
    invalid_ip,
):
    pseudo_header_values["src_ip"] = invalid_ip

    with pytest.raises(ipaddress.AddressValueError):
        build_pseudo_header(**pseudo_header_values)


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.168.1.1",
        "192.168.1",
        "not_an_ip",
        "",
        "2001:db8::1",
    ],
)
def test_build_pseudo_header_invalid_destination_ip(
    pseudo_header_values,
    invalid_ip,
):
    pseudo_header_values["dst_ip"] = invalid_ip

    with pytest.raises(ipaddress.AddressValueError):
        build_pseudo_header(**pseudo_header_values)


def test_build_pseudo_header_zero_values():
    result = build_pseudo_header(
        src_ip="0.0.0.0",
        dst_ip="0.0.0.0",
        protocol=0,
        length=0,
    )

    assert result == b"\x00" * 12


def test_build_pseudo_header_maximum_values():
    result = build_pseudo_header(
        src_ip="255.255.255.255",
        dst_ip="255.255.255.255",
        protocol=255,
        length=65535,
    )

    assert result == (b"\xff" * 8 + b"\x00\xff" + b"\xff\xff")


def test_build_pseudo_header_does_not_modify_inputs(
    pseudo_header_values,
):
    original = pseudo_header_values.copy()

    build_pseudo_header(**pseudo_header_values)

    assert pseudo_header_values == original


@pytest.mark.parametrize(
    "value, bits",
    [
        (0, 8),
        (1, 8),
        (255, 8),
        (0, 16),
        (65535, 16),
        (0, 32),
        (4294967295, 32),
        (0, 64),
        ((1 << 64) - 1, 64),
    ],
)
def test_validate_uint_valid_values(value, bits):
    assert validate_uint(value, bits, "value") is None


@pytest.mark.parametrize(
    "value, bits",
    [
        (-1, 8),
        (-1, 16),
        (-100, 32),
        (256, 8),
        (65536, 16),
        (4294967296, 32),
    ],
)
def test_validate_uint_out_of_range(value, bits):
    with pytest.raises(
        ValueError,
        match="must fit in",
    ):
        validate_uint(value, bits, "value")


@pytest.mark.parametrize(
    "value",
    [
        1.5,
        1.0,
        "123",
        "10",
        None,
        [],
        {},
        (),
        b"\x01",
        complex(1, 2),
    ],
)
def test_validate_uint_invalid_type(value):
    with pytest.raises(
        ValueError,
        match="must be an integer",
    ):
        validate_uint(value, 16, "value")


@pytest.mark.parametrize(
    "value",
    [True, False],
)
def test_validate_uint_rejects_boolean(value):
    with pytest.raises(
        ValueError,
        match="must be an integer",
    ):
        validate_uint(value, 8, "value")
