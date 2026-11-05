import struct

import pytest

from netlayers.checksum import internet_checksum
from netlayers.constant import (
    IP_PROTO_UDP,
    UDP_HEADER_LENGTH,
    UDP_MAX_LENGTH,
    UDP_ZERO_CHECKSUM_SUBSTITUTE,
)
from netlayers.udp import _pack_udp, build_udp_datagram, parse_udp
from netlayers.utils import build_pseudo_header


@pytest.fixture
def udp_values():
    return {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 12345,
        "dst_port": 53,
        "payload": b"Hello UDP!",
    }


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


def test_pack_udp_header_fields():
    result = _pack_udp(
        src_port=12345,
        dst_port=80,
        length=100,
        checksum=1234,
    )

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", result)

    assert src_port == 12345
    assert dst_port == 80
    assert length == 100
    assert checksum == 1234


def test_pack_udp_default_checksum():
    result = _pack_udp(12345, 80, 8)

    checksum = struct.unpack("!H", result[6:8])[0]

    assert checksum == 0


def test_pack_udp_zero_values():
    result = _pack_udp(0, 0, 0)

    assert result == b"\x00" * 8


@pytest.mark.parametrize(
    "src_port, dst_port, length, checksum",
    [
        (65535, 65535, 65535, 65535),
        (0, 0, 0, 0),
        (1, 2, 8, 100),
        (53, 443, 512, 12345),
    ],
)
def test_pack_udp_various_values(
    src_port,
    dst_port,
    length,
    checksum,
):
    result = _pack_udp(
        src_port,
        dst_port,
        length,
        checksum,
    )

    assert struct.unpack("!HHHH", result) == (
        src_port,
        dst_port,
        length,
        checksum,
    )


def test_build_udp_datagram_minimum_length():
    datagram = build_udp_datagram(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=12345,
        dst_port=53,
    )

    assert len(datagram) == UDP_HEADER_LENGTH


def test_build_udp_datagram_with_payload(udp_values):
    datagram = build_udp_datagram(**udp_values)

    assert datagram[UDP_HEADER_LENGTH:] == udp_values["payload"]


def test_build_udp_datagram_header_length(udp_values):
    datagram = build_udp_datagram(**udp_values)

    assert len(datagram) == UDP_HEADER_LENGTH + len(udp_values["payload"])


def test_build_udp_datagram_checksum(udp_values):
    datagram = build_udp_datagram(**udp_values)

    length = len(datagram)

    pseudo_header = build_pseudo_header(
        udp_values["src_ip"],
        udp_values["dst_ip"],
        IP_PROTO_UDP,
        length,
    )

    # Checksum over pseudo-header and complete UDP datagram
    # must be zero.
    assert internet_checksum(pseudo_header + datagram) == 0


def test_build_udp_datagram_empty_payload(udp_values):
    udp_values["payload"] = b""

    datagram = build_udp_datagram(**udp_values)

    assert len(datagram) == UDP_HEADER_LENGTH
    assert datagram[UDP_HEADER_LENGTH:] == b""


def test_build_udp_datagram_odd_payload(udp_values):
    udp_values["payload"] = b"ABC"

    datagram = build_udp_datagram(**udp_values)

    assert datagram[UDP_HEADER_LENGTH:] == b"ABC"

    pseudo_header = build_pseudo_header(
        udp_values["src_ip"],
        udp_values["dst_ip"],
        IP_PROTO_UDP,
        len(datagram),
    )

    assert internet_checksum(pseudo_header + datagram) == 0


def test_build_udp_datagram_checksum_changes_with_payload(
    udp_values,
):
    udp_values["payload"] = b"Hello"
    datagram1 = build_udp_datagram(**udp_values)

    udp_values["payload"] = b"World"
    datagram2 = build_udp_datagram(**udp_values)

    checksum1 = struct.unpack("!H", datagram1[6:8])[0]
    checksum2 = struct.unpack("!H", datagram2[6:8])[0]

    assert checksum1 != checksum2


@pytest.mark.parametrize(
    "src_port",
    [-1, 65536, 100000],
)
def test_build_udp_datagram_invalid_source_port(
    udp_values,
    src_port,
):
    udp_values["src_port"] = src_port

    with pytest.raises(
        ValueError,
        match="Source port must fit in 16 bits",
    ):
        build_udp_datagram(**udp_values)


@pytest.mark.parametrize(
    "dst_port",
    [-1, 65536, 100000],
)
def test_build_udp_datagram_invalid_destination_port(
    udp_values,
    dst_port,
):
    udp_values["dst_port"] = dst_port

    with pytest.raises(
        ValueError,
        match="Destination port must fit in 16 bits",
    ):
        build_udp_datagram(**udp_values)


@pytest.mark.parametrize(
    "port",
    [0, 1, 65535],
)
def test_build_udp_datagram_valid_source_port(
    udp_values,
    port,
):
    udp_values["src_port"] = port

    datagram = build_udp_datagram(**udp_values)

    actual_port = struct.unpack("!H", datagram[:2])[0]

    assert actual_port == port


@pytest.mark.parametrize(
    "port",
    [0, 1, 65535],
)
def test_build_udp_datagram_valid_destination_port(
    udp_values,
    port,
):
    udp_values["dst_port"] = port

    datagram = build_udp_datagram(**udp_values)

    actual_port = struct.unpack("!H", datagram[2:4])[0]

    assert actual_port == port


@pytest.mark.parametrize(
    "port",
    [True, False, 1.5, "123", None],
)
def test_build_udp_datagram_invalid_source_port_type(
    udp_values,
    port,
):
    udp_values["src_port"] = port

    with pytest.raises(ValueError):
        build_udp_datagram(**udp_values)


@pytest.mark.parametrize(
    "src_ip",
    [
        "999.168.1.1",
        "192.168.1",
        "invalid",
        "",
        "2001:db8::1",
    ],
)
def test_build_udp_datagram_invalid_source_ip(
    udp_values,
    src_ip,
):
    udp_values["src_ip"] = src_ip

    with pytest.raises(ValueError):
        build_udp_datagram(**udp_values)


@pytest.mark.parametrize(
    "dst_ip",
    [
        "999.168.1.1",
        "192.168.1",
        "invalid",
        "",
        "2001:db8::1",
    ],
)
def test_build_udp_datagram_invalid_destination_ip(
    udp_values,
    dst_ip,
):
    udp_values["dst_ip"] = dst_ip

    with pytest.raises(ValueError):
        build_udp_datagram(**udp_values)


def test_build_udp_datagram_maximum_length():
    payload_size = UDP_MAX_LENGTH - UDP_HEADER_LENGTH
    payload = b"A" * payload_size

    datagram = build_udp_datagram(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=12345,
        dst_port=53,
        payload=payload,
    )

    assert len(datagram) == UDP_MAX_LENGTH

    length = struct.unpack("!H", datagram[4:6])[0]

    assert length == UDP_MAX_LENGTH


def test_build_udp_datagram_exceeds_maximum_length():
    payload_size = UDP_MAX_LENGTH - UDP_HEADER_LENGTH + 1
    payload = b"A" * payload_size

    with pytest.raises(
        ValueError,
        match="UDP datagram is too large",
    ):
        build_udp_datagram(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=12345,
            dst_port=53,
            payload=payload,
        )
