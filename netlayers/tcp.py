import struct
from typing import Any

from netlayers.checksum import internet_checksum
from netlayers.constant import IP_PROTO_TCP, TCP_MIN_HEADER_LENGTH
from netlayers.utils import build_pseudo_header, validate_uint


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


def build_tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    sequence_num: int,
    ack_num: int = 0,
    flags: int = 0,
    window_size: int = 64240,
    urgent_pointer: int = 0,
    payload: bytes = b"",
    options: bytes = b"",
) -> bytes:

    validate_uint(src_port, 16, "Source port")
    validate_uint(dst_port, 16, "Destination port")
    validate_uint(window_size, 16, "Window size")
    validate_uint(urgent_pointer, 16, "Urgent pointer")
    validate_uint(sequence_num, 32, "Sequence number")
    validate_uint(ack_num, 32, "ACK num")
    validate_uint(flags, 8, "Flags")

    offset = (TCP_MIN_HEADER_LENGTH + len(options)) // 4
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        sequence_num,
        ack_num,
        (offset << 4),
        flags,
        window_size,
        0,
        urgent_pointer,
    )

    segment = header + options + payload

    pseudo_header = build_pseudo_header(src_ip, dst_ip, IP_PROTO_TCP, len(segment))

    checksum = internet_checksum(pseudo_header + segment)

    segment = segment[:16] + struct.pack("!H", checksum) + segment[18:]

    return segment
