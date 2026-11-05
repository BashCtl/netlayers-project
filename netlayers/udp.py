import struct
from typing import Any

from netlayers.checksum import internet_checksum
from netlayers.constant import (
    IP_PROTO_UDP,
    UDP_HEADER_LENGTH,
    UDP_MAX_LENGTH,
    UDP_ZERO_CHECKSUM_SUBSTITUTE,
)
from netlayers.utils import build_pseudo_header, validate_uint


def parse_udp(ipv4_payload: bytes) -> dict[str, Any]:
    if len(ipv4_payload) < UDP_HEADER_LENGTH:
        raise ValueError("Truncated UDP header")

    src_port, dst_port, length, checksum = struct.unpack_from("!HHHH", ipv4_payload, 0)

    if length < UDP_HEADER_LENGTH:
        raise ValueError("Malformed UDP packet: length smaller than header")

    payload = ipv4_payload[UDP_HEADER_LENGTH:length]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
        "payload": payload,
    }


def _pack_udp(src_port: int, dst_port: int, length: int, checksum: int = 0) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)


def build_udp_datagram(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
) -> bytes:
    validate_uint(src_port, 16, "Source port")
    validate_uint(dst_port, 16, "Destination port")

    length = UDP_HEADER_LENGTH + len(payload)

    if length > UDP_MAX_LENGTH:
        raise ValueError("UDP datagram is too large")

    udp_header_no_checksum = _pack_udp(src_port, dst_port, length)

    pseudo_header = build_pseudo_header(src_ip, dst_ip, IP_PROTO_UDP, length)

    datagram = udp_header_no_checksum + payload
    checksum = internet_checksum(pseudo_header + datagram)

    if checksum == 0:
        checksum = UDP_ZERO_CHECKSUM_SUBSTITUTE

    return _pack_udp(src_port, dst_port, length, checksum) + payload
