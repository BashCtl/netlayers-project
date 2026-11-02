import struct

import pytest

from netlayers.constant import UDP_HEADER_LENGTH
from netlayers.udp import parse_udp


def build_udp_packet(
    src_port: int = 12345,
    dst_port: int = 53,
    payload: bytes = b"hello",
    checksum: int = 0x1234,
) -> bytes:
    length = UDP_HEADER_LENGTH + len(payload)

    header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        length,
        checksum,
    )

    return header + payload


def test_parse_udp_valid_packet():
    packet = build_udp_packet()

    result = parse_udp(packet)

    assert result == {
        "src_port": 12345,
        "dst_port": 53,
        "length": UDP_HEADER_LENGTH + 5,
        "checksum": 0x1234,
        "payload": b"hello",
    }


def test_parse_udp_empty_payload():
    packet = build_udp_packet(payload=b"")

    result = parse_udp(packet)

    assert result["src_port"] == 12345
    assert result["dst_port"] == 53
    assert result["length"] == UDP_HEADER_LENGTH
    assert result["checksum"] == 0x1234
    assert result["payload"] == b""


def test_parse_udp_custom_ports():
    packet = build_udp_packet(
        src_port=8080,
        dst_port=443,
        payload=b"data",
    )

    result = parse_udp(packet)

    assert result["src_port"] == 8080
    assert result["dst_port"] == 443
    assert result["payload"] == b"data"


def test_parse_udp_max_port_values():
    packet = build_udp_packet(
        src_port=65535,
        dst_port=65535,
    )

    result = parse_udp(packet)

    assert result["src_port"] == 65535
    assert result["dst_port"] == 65535


def test_parse_udp_truncated_header():
    packet = b"\x00" * (UDP_HEADER_LENGTH - 1)

    with pytest.raises(ValueError, match="Truncated UDP header"):
        parse_udp(packet)


def test_parse_udp_empty_packet():
    with pytest.raises(ValueError, match="Truncated UDP header"):
        parse_udp(b"")


@pytest.mark.parametrize("length", [0, 1, 4, 7])
def test_parse_udp_length_smaller_than_header(length):
    packet = struct.pack(
        "!HHHH",
        12345,
        53,
        length,
        0x1234,
    )

    with pytest.raises(
        ValueError,
        match="Malformed UDP packet: length smaller than header",
    ):
        parse_udp(packet)


def test_parse_udp_payload_larger_than_declared_length():
    packet = (
        struct.pack(
            "!HHHH",
            12345,
            53,
            UDP_HEADER_LENGTH + 2,
            0x1234,
        )
        + b"hello"
    )

    result = parse_udp(packet)

    assert result["payload"] == b"he"
    assert result["length"] == UDP_HEADER_LENGTH + 2
