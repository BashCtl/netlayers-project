import struct
from typing import Any

from netlayers.constant import (
    ICMP_COMMON_LEN,
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    ICMP_HEADER_LEN,
)


def parse_icmp(ipv4_payload: bytes) -> dict[str, Any]:
    if len(ipv4_payload) < ICMP_HEADER_LEN:
        raise ValueError("Invalid ICMP packet")

    (
        icmp_type,
        code,
        checksum,
    ) = struct.unpack_from("!BBH", ipv4_payload, 0)
    rest_of_header = ipv4_payload[ICMP_COMMON_LEN:ICMP_HEADER_LEN]
    payload = ipv4_payload[ICMP_HEADER_LEN:]

    result = {
        "type": icmp_type,
        "code": code,
        "checksum": checksum,
        "rest_of_header": rest_of_header,
        "payload": payload,
    }

    if icmp_type in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST):
        identifier, sequence = struct.unpack("!HH", rest_of_header)
        result["identifier"] = identifier
        result["sequence"] = sequence

    return result
