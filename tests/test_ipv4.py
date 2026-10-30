import socket
import struct

import pytest

from netlayers.ipv4 import parse_ipv4


def build_ipv4_packet(
    version=4,
    ihl=5,
    ttl=64,
    protocol=6,
    src_ip="192.168.1.1",
    dst_ip="192.168.1.2",
    payload=b"Hello",
    total_length=None,
):

    header_length = ihl * 4

    if total_length is None:
        total_length = header_length + len(payload)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) | ihl,
        0,
        total_length,
        1234,
        0,
        ttl,
        protocol,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    # Add padding for IPv4 options if needed.
    header += b"\x00" * (header_length - len(header))

    return header + payload


class TestParseIPv4:
    def test_parse_valid_packet(self):
        packet = build_ipv4_packet()

        result = parse_ipv4(packet)

        assert result == {
            "version": 4,
            "ihl": 5,
            "ttl": 64,
            "protocol": 6,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "total_length": 25,
            "payload": b"Hello",
        }

    def test_parse_empty_payload(self):
        packet = build_ipv4_packet(payload=b"")

        result = parse_ipv4(packet)

        assert result["payload"] == b""
        assert result["total_length"] == 20

    def test_parse_custom_ttl(self):
        packet = build_ipv4_packet(ttl=128)

        result = parse_ipv4(packet)

        assert result["ttl"] == 128

    def test_parse_custom_protocol(self):
        packet = build_ipv4_packet(protocol=17)

        result = parse_ipv4(packet)

        assert result["protocol"] == 17

    def test_parse_custom_ip_addresses(self):
        packet = build_ipv4_packet(src_ip="10.0.0.1", dst_ip="8.8.8.8")

        result = parse_ipv4(packet)

        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "8.8.8.8"

    def test_parse_ipv4_options(self):
        packet = build_ipv4_packet(ihl=6)

        result = parse_ipv4(packet)

        assert result["ihl"] == 6
        assert result["payload"] == b"Hello"

    def test_payload_respects_total_length(self):
        packet = build_ipv4_packet(payload=b"HelloExtra")

        packet += b"ExtraData"

        result = parse_ipv4(packet)

        assert result["payload"] == b"HelloExtra"
        assert b"ExtraData" not in result["payload"]

    def test_truncated_header_raises_error(self):
        packet = b"\x45" * 19

        with pytest.raises(ValueError, match="Truncated IPv4 header"):
            parse_ipv4(packet)

    def test_invalid_ipv4_version_raises_error(self):
        packet = build_ipv4_packet(version=6)

        with pytest.raises(ValueError, match="Not an IPv4 packet"):
            parse_ipv4(packet)

    def test_invalid_ihl_zero_raises_error(self):
        packet = build_ipv4_packet(ihl=0)

        with pytest.raises(ValueError, match="Invalid IPv4 header length"):
            parse_ipv4(packet)

    def test_invalid_ihl_less_than_minimum_raises_error(self):
        packet = build_ipv4_packet(ihl=4)

        with pytest.raises(ValueError, match="Invalid IPv4 header length"):
            parse_ipv4(packet)

    def test_truncated_header_with_ptions_raises_error(self):
        packet = build_ipv4_packet(ihl=6)[:20]

        with pytest.raises(ValueError, match="Truncated IPv4 header"):
            parse_ipv4(packet)

    def test_total_length_smaller_than_header_raises_error(self):
        packet = build_ipv4_packet(total_length=19)

        with pytest.raises(
            ValueError,
            match="Malformed IPv4 packet: total length smaller than header length",
        ):
            parse_ipv4(packet)

    def test_total_length_equal_to_header_length(self):
        packet = build_ipv4_packet(payload=b"", total_length=20)

        result = parse_ipv4(packet)

        assert result["total_length"] == 20
        assert result["payload"] == b""

    def test_total_length_larger_than_available_packet(self):
        packet = build_ipv4_packet(payload=b"Hello", total_length=100)

        result = parse_ipv4(packet)

        assert result["payload"] == b"Hello"
