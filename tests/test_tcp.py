import struct

import pytest

from netlayers.constant import TCP_MIN_HEADER_LENGTH
from netlayers.tcp import parse_tcp


@pytest.fixture
def tcp_frame():
    return bytes.fromhex(
        "1a46f73375a89660f528217508004500003c534940004006d370"
        "0a0000010a000002aad21f90ef0ccbe900000000a002faf014310000"
        "020405b40402080ab8f55813000000000103030a"
    )


def build_tcp_header(
    src_port=12345,
    dst_port=80,
    sequence_num=1000,
    ack_num=2000,
    offset=5,
    flags=0x02,
    window_size=64240,
    checksum=0x1234,
    urgent_pointer=0,
):
    offset_reserved = offset << 4

    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        sequence_num,
        ack_num,
        offset_reserved,
        flags,
        window_size,
        checksum,
        urgent_pointer,
    )

    if offset >= 5:
        header += bytes((offset * 4) - TCP_MIN_HEADER_LENGTH)

    return header


def test_parse_tcp_valid_header():
    tcp_data = build_tcp_header()

    result = parse_tcp(tcp_data)

    assert result["src_port"] == 12345
    assert result["dst_port"] == 80
    assert result["sequence_num"] == 1000
    assert result["ack_num"] == 2000
    assert result["header_length"] == 20
    assert result["flags"] == 0x02
    assert result["window_size"] == 64240
    assert result["checksum"] == 0x1234
    assert result["urgent_pointer"] == 0
    assert result["payload"] == b""


def test_parse_tcp_with_payload():
    payload = b"Hello, TCP!"
    tcp_data = build_tcp_header() + payload

    result = parse_tcp(tcp_data)

    assert result["payload"] == payload
    assert result["header_length"] == 20


def test_parse_tcp_with_options():
    options = bytes.fromhex("020405b4")
    payload = b"test"

    tcp_data = build_tcp_header(offset=6)[:20] + options + payload

    result = parse_tcp(tcp_data)

    assert result["header_length"] == 24
    assert result["payload"] == payload


def test_parse_tcp_truncated_header():
    tcp_data = b"\x00" * (TCP_MIN_HEADER_LENGTH - 1)

    with pytest.raises(ValueError, match="Truncated TCP header"):
        parse_tcp(tcp_data)


def test_parse_tcp_invalid_header_length():
    tcp_data = build_tcp_header(offset=4)

    with pytest.raises(ValueError, match="Invalid TCP header length"):
        parse_tcp(tcp_data)


def test_parse_tcp_truncated_options():
    tcp_data = build_tcp_header(offset=6)[:20]

    with pytest.raises(ValueError, match="Truncated TCP header"):
        parse_tcp(tcp_data)


def test_parse_tcp_with_example_frame(tcp_frame):
    # Ethernet header: 14 bytes
    # IPv4 header: 20 bytes
    # TCP header starts at byte 34.
    tcp_data = tcp_frame[34:]

    result = parse_tcp(tcp_data)

    assert result["src_port"] == 0xAAD2
    assert result["dst_port"] == 0x1F90
    assert result["sequence_num"] == 0xEF0CCBE9
    assert result["ack_num"] == 0
    assert result["header_length"] == 40
    assert result["flags"] == 0x02
    assert result["window_size"] == 0xFAF0
    assert result["checksum"] == 0x1431
    assert result["urgent_pointer"] == 0
    assert result["payload"] == b""
