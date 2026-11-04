import struct

import pytest

from netlayers.checksum import internet_checksum
from netlayers.constant import IP_PROTO_TCP, TCP_MIN_HEADER_LENGTH
from netlayers.tcp import build_tcp_segment, parse_tcp
from netlayers.utils import build_pseudo_header


@pytest.fixture
def tcp_frame():
    return bytes.fromhex(
        "1a46f73375a89660f528217508004500003c534940004006d370"
        "0a0000010a000002aad21f90ef0ccbe900000000a002faf014310000"
        "020405b40402080ab8f55813000000000103030a"
    )


@pytest.fixture
def tcp_values():
    return {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 12345,
        "dst_port": 80,
        "sequence_num": 1000,
        "ack_num": 2000,
        "flags": 0x18,  # PSH + ACK
        "window_size": 64240,
        "urgent_pointer": 0,
        "payload": b"Hello TCP!",
        "options": b"",
    }


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


def test_build_tcp_segment_returns_bytes(tcp_values):
    segment = build_tcp_segment(**tcp_values)

    assert isinstance(segment, bytes)


def test_build_tcp_segment_minimum_header_length(tcp_values):
    tcp_values["payload"] = b""

    segment = build_tcp_segment(**tcp_values)

    assert len(segment) == 20


def test_build_tcp_segment_with_payload(tcp_values):
    segment = build_tcp_segment(**tcp_values)

    assert segment[20:] == tcp_values["payload"]
    assert len(segment) == 20 + len(tcp_values["payload"])


def test_build_tcp_segment_header_fields(tcp_values):
    segment = build_tcp_segment(**tcp_values)

    (
        src_port,
        dst_port,
        sequence_num,
        ack_num,
        offset_reserved,
        flags,
        window_size,
        checksum,
        urgent_pointer,
    ) = struct.unpack("!HHIIBBHHH", segment[:20])

    assert src_port == tcp_values["src_port"]
    assert dst_port == tcp_values["dst_port"]
    assert sequence_num == tcp_values["sequence_num"]
    assert ack_num == tcp_values["ack_num"]
    assert flags == tcp_values["flags"]
    assert window_size == tcp_values["window_size"]
    assert urgent_pointer == tcp_values["urgent_pointer"]
    assert checksum != 0


def test_build_tcp_segment_data_offset(tcp_values):
    segment = build_tcp_segment(**tcp_values)

    offset_reserved = segment[12]
    data_offset = offset_reserved >> 4

    assert data_offset == 5
    assert data_offset * 4 == 20


def test_build_tcp_segment_default_values():
    segment = build_tcp_segment(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=12345,
        dst_port=80,
        sequence_num=1000,
    )

    (
        src_port,
        dst_port,
        sequence_num,
        ack_num,
        offset_reserved,
        flags,
        window_size,
        checksum,
        urgent_pointer,
    ) = struct.unpack("!HHIIBBHHH", segment[:20])

    assert ack_num == 0
    assert flags == 0
    assert window_size == 64240
    assert urgent_pointer == 0
    assert segment[20:] == b""


def test_build_tcp_segment_with_options(tcp_values):
    # Four bytes of TCP options
    options = b"\x01\x01\x01\x01"
    tcp_values["options"] = options

    segment = build_tcp_segment(**tcp_values)

    data_offset = segment[12] >> 4

    assert data_offset == 6
    assert data_offset * 4 == 24
    assert segment[20:24] == options
    assert segment[24:] == tcp_values["payload"]


def test_build_tcp_segment_checksum(tcp_values):
    segment = build_tcp_segment(**tcp_values)

    pseudo_header = build_pseudo_header(
        tcp_values["src_ip"],
        tcp_values["dst_ip"],
        IP_PROTO_TCP,
        len(segment),
    )

    # Checksum of pseudo-header + complete TCP segment must be zero.
    assert internet_checksum(pseudo_header + segment) == 0


def test_build_tcp_segment_checksum_with_odd_payload(tcp_values):
    tcp_values["payload"] = b"ABC"

    segment = build_tcp_segment(**tcp_values)

    pseudo_header = build_pseudo_header(
        tcp_values["src_ip"],
        tcp_values["dst_ip"],
        IP_PROTO_TCP,
        len(segment),
    )

    assert internet_checksum(pseudo_header + segment) == 0


def test_build_tcp_segment_different_payloads_different_checksums(
    tcp_values,
):
    tcp_values["payload"] = b"Hello"
    segment1 = build_tcp_segment(**tcp_values)

    tcp_values["payload"] = b"World"
    segment2 = build_tcp_segment(**tcp_values)

    checksum1 = struct.unpack("!H", segment1[16:18])[0]
    checksum2 = struct.unpack("!H", segment2[16:18])[0]

    assert checksum1 != checksum2


def test_build_tcp_segment_max_ports(tcp_values):
    tcp_values["src_port"] = 65535
    tcp_values["dst_port"] = 65535

    segment = build_tcp_segment(**tcp_values)

    src_port, dst_port = struct.unpack("!HH", segment[:4])

    assert src_port == 65535
    assert dst_port == 65535


def test_build_tcp_segment_with_large_payload(tcp_values):
    tcp_values["payload"] = b"A" * 1400

    segment = build_tcp_segment(**tcp_values)

    assert len(segment) == 20 + 1400
    assert segment[20:] == tcp_values["payload"]

    pseudo_header = build_pseudo_header(
        tcp_values["src_ip"],
        tcp_values["dst_ip"],
        IP_PROTO_TCP,
        len(segment),
    )

    assert internet_checksum(pseudo_header + segment) == 0

def test_build_tcp_segment_payload_not_modified(tcp_values):
    original_payload = tcp_values["payload"]

    build_tcp_segment(**tcp_values)

    assert tcp_values["payload"] == original_payload