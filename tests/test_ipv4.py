import socket
import struct

import pytest

from netlayers.checksum import internet_checksum
from netlayers.ipv4 import (
    _pack_ipv4,
    build_ipv4_packet,
    parse_ipv4,
)


def make_ipv4_packet(
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
        packet = make_ipv4_packet()

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
        packet = make_ipv4_packet(payload=b"")

        result = parse_ipv4(packet)

        assert result["payload"] == b""
        assert result["total_length"] == 20

    def test_parse_custom_ttl(self):
        packet = make_ipv4_packet(ttl=128)

        result = parse_ipv4(packet)

        assert result["ttl"] == 128

    def test_parse_custom_protocol(self):
        packet = make_ipv4_packet(protocol=17)

        result = parse_ipv4(packet)

        assert result["protocol"] == 17

    def test_parse_custom_ip_addresses(self):
        packet = make_ipv4_packet(src_ip="10.0.0.1", dst_ip="8.8.8.8")

        result = parse_ipv4(packet)

        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "8.8.8.8"

    def test_parse_ipv4_options(self):
        packet = make_ipv4_packet(ihl=6)

        result = parse_ipv4(packet)

        assert result["ihl"] == 6
        assert result["payload"] == b"Hello"


class TestPackIPv4:
    def test_packs_fields_in_network_byte_order(self):
        packed = _pack_ipv4(
            0x45,
            0x10,
            0x1234,
            0x5678,
            0x4000,
            64,
            17,
            0x9ABC,
            socket.inet_aton("192.0.2.1"),
            socket.inet_aton("198.51.100.2"),
        )

        assert packed == struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0x10,
            0x1234,
            0x5678,
            0x4000,
            64,
            17,
            0x9ABC,
            socket.inet_aton("192.0.2.1"),
            socket.inet_aton("198.51.100.2"),
        )
        assert len(packed) == 20


class TestBuildIPv4Packet:
    def test_builds_packet_with_defaults_and_valid_checksum(self):
        packet = build_ipv4_packet("192.0.2.1", "198.51.100.2", 17, b"data")

        fields = struct.unpack("!BBHHHBBH4s4s", packet[:20])
        assert fields == (
            0x45,
            0,
            24,
            0,
            0x4000,
            64,
            17,
            fields[7],
            socket.inet_aton("192.0.2.1"),
            socket.inet_aton("198.51.100.2"),
        )
        assert internet_checksum(packet[:20]) == 0
        assert packet[20:] == b"data"

    def test_builds_packet_with_custom_fields_and_without_df(self):
        packet = build_ipv4_packet(
            "10.0.0.1",
            "10.0.0.2",
            6,
            b"payload",
            ttl=32,
            identification=0x1234,
            dont_fragment=False,
        )

        fields = struct.unpack("!BBHHHBBH4s4s", packet[:20])
        assert fields[2:7] == (27, 0x1234, 0, 32, 6)
        assert fields[8:] == (
            socket.inet_aton("10.0.0.1"),
            socket.inet_aton("10.0.0.2"),
        )
        assert packet[20:] == b"payload"
        assert internet_checksum(packet[:20]) == 0

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"protocol": 256}, "Protocol"),
            ({"protocol": 17, "ttl": -1}, "TTL"),
            ({"protocol": 17, "identification": 65536}, "Identification"),
            ({"protocol": 17, "payload": "not bytes"}, "Payload must be bytes"),
        ],
    )
    def test_rejects_invalid_values(self, kwargs, message):
        with pytest.raises(ValueError, match=message):
            build_ipv4_packet("192.0.2.1", "198.51.100.2", **kwargs)

    def test_rejects_packet_larger_than_ipv4_limit(self):
        with pytest.raises(ValueError, match="IPv4 packet is too large"):
            build_ipv4_packet("192.0.2.1", "198.51.100.2", 17, b"x" * 65516)


class TestParseIPv4Validation:
    def test_payload_respects_total_length(self):
        packet = make_ipv4_packet(payload=b"HelloExtra")

        packet += b"ExtraData"

        result = parse_ipv4(packet)

        assert result["payload"] == b"HelloExtra"
        assert b"ExtraData" not in result["payload"]

    def test_truncated_header_raises_error(self):
        packet = b"\x45" * 19

        with pytest.raises(ValueError, match="Truncated IPv4 header"):
            parse_ipv4(packet)

    def test_invalid_ipv4_version_raises_error(self):
        packet = make_ipv4_packet(version=6)

        with pytest.raises(ValueError, match="Not an IPv4 packet"):
            parse_ipv4(packet)

    def test_invalid_ihl_zero_raises_error(self):
        packet = make_ipv4_packet(ihl=0)

        with pytest.raises(ValueError, match="Invalid IPv4 header length"):
            parse_ipv4(packet)

    def test_invalid_ihl_less_than_minimum_raises_error(self):
        packet = make_ipv4_packet(ihl=4)

        with pytest.raises(ValueError, match="Invalid IPv4 header length"):
            parse_ipv4(packet)

    def test_truncated_header_with_options_raises_error(self):
        packet = make_ipv4_packet(ihl=6)[:20]

        with pytest.raises(ValueError, match="Truncated IPv4 header"):
            parse_ipv4(packet)

    def test_total_length_smaller_than_header_raises_error(self):
        packet = make_ipv4_packet(total_length=19)

        with pytest.raises(
            ValueError,
            match="Malformed IPv4 packet: total length smaller than header length",
        ):
            parse_ipv4(packet)

    def test_total_length_equal_to_header_length(self):
        packet = make_ipv4_packet(payload=b"", total_length=20)

        result = parse_ipv4(packet)

        assert result["total_length"] == 20
        assert result["payload"] == b""

    def test_total_length_larger_than_available_packet(self):
        packet = make_ipv4_packet(payload=b"Hello", total_length=100)

        result = parse_ipv4(packet)

        assert result["payload"] == b"Hello"
