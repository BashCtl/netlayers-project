import struct
from typing import Any

from netlayers.constant import UDP_HEADER_LENGTH


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
