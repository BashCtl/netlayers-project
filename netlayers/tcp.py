import struct
from typing import Any

from netlayers.constant import TCP_MIN_HEADER_LENGTH


def parse_tcp(ipv4_payload) -> dict[str, Any]:
    if len(ipv4_payload) < TCP_MIN_HEADER_LENGTH:
        raise ValueError("Truncated TCP header")
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
    ) = struct.unpack_from("!HHIIBBHHH", ipv4_payload, 0)

    offset = offset_reserved >> 4
    header_length_bytes = offset * 4

    if offset < 5:
        raise ValueError("Invalid TCP header length")

    if len(ipv4_payload) < header_length_bytes:
        raise ValueError("Truncated TCP header")

    payload = ipv4_payload[header_length_bytes:]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "sequence_num": sequence_num,
        "ack_num": ack_num,
        "header_length": header_length_bytes,
        "flags": flags,
        "window_size": window_size,
        "checksum": checksum,
        "urgent_pointer": urgent_pointer,
        "payload": payload,
    }
