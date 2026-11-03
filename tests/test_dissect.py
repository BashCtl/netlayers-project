import socket
import struct

from netlayers.dissect import dissect


def build_ethernet_frame(ethertype, payload):
    return (
        b"\x66\x47\x51\x6b\x63\xcc\x00\x11\x22\x33\x44\x55"
        + struct.pack("!H", ethertype)
        + payload
    )


def build_ipv4_packet(protocol, payload):
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        1,
        0,
        64,
        protocol,
        0,
        socket.inet_aton("192.168.1.1"),
        socket.inet_aton("192.168.1.2"),
    )
    return header + payload


def test_dissect_ipv4_icmp_frame():
    icmp = struct.pack("!BBHHH", 8, 0, 0xF7FF, 1, 1) + b"data"
    frame = build_ethernet_frame(0x0800, build_ipv4_packet(1, icmp))

    result = dissect(frame)

    assert result["ethernet"]["ethertype"] == 0x0800
    assert result["ipv4"]["src_ip"] == "192.168.1.1"
    assert result["ipv4"]["dst_ip"] == "192.168.1.2"
    assert result["icmp"] == {
        "type": 8,
        "code": 0,
        "checksum": 0xF7FF,
        "rest_of_header": b"\x00\x01\x00\x01",
        "payload": b"data",
        "identifier": 1,
        "sequence": 1,
    }
    assert "error" not in result


def test_dissect_unknown_ethertype_returns_ethernet_only():
    result = dissect(build_ethernet_frame(0x88B5, b"payload"))

    assert result["ethernet"]["ethertype"] == 0x88B5
    assert result["ethernet"]["payload"] == b"payload"
    assert set(result) == {"ethernet"}


def test_dissect_unsupported_ipv4_protocol_returns_ipv4_only():
    frame = build_ethernet_frame(0x0800, build_ipv4_packet(99, b"payload"))

    result = dissect(frame)

    assert result["ipv4"]["protocol"] == 99
    assert result["ipv4"]["payload"] == b"payload"
    assert "icmp" not in result
    assert "tcp" not in result
    assert "udp" not in result


def test_dissect_records_ipv4_parse_error():
    frame = build_ethernet_frame(0x0800, b"short")

    result = dissect(frame)

    assert result["ethernet"]["ethertype"] == 0x0800
    assert result["error"] == "Truncated IPv4 header"
    assert "ipv4" not in result


def test_dissect_records_transport_parse_error():
    frame = build_ethernet_frame(0x0800, build_ipv4_packet(1, b"short"))

    result = dissect(frame)

    assert result["ipv4"]["protocol"] == 1
    assert result["error"] == "Invalid ICMP packet"
    assert "icmp" not in result
