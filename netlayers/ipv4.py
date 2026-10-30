import socket
import struct

from netlayers.constant import IPV4_MIN_HEADER_LENGTH, IPV4_MIN_IHL, LOWER_NIBBLE_MASK


def parse_ipv4(packet: bytes) -> dict:
    if len(packet) < IPV4_MIN_HEADER_LENGTH:
        raise ValueError("Truncated IPv4 header")

    (
        version_ihl,
        _tos,
        total_length,
        _ident,
        _flags_frag,
        ttl,
        protocol,
        _checksum,
        src_raw,
        dst_raw,
    ) = struct.unpack_from("!BBHHHBBH4s4s", packet, 0)

    version = version_ihl >> 4
    if version != 4:
        raise ValueError("Not an IPv4 packet")

    ihl = version_ihl & LOWER_NIBBLE_MASK
    if ihl < IPV4_MIN_IHL:
        raise ValueError("Invalid IPv4 header length")

    header_length_bytes = ihl * 4
    if len(packet) < header_length_bytes:
        raise ValueError("Truncated IPv4 header")

    if total_length < header_length_bytes:
        raise ValueError(
            "Malformed IPv4 packet: total length smaller than header length"
        )

    return {
        "version": version,
        "ihl": ihl,
        "ttl": ttl,
        "protocol": protocol,
        "src_ip": socket.inet_ntoa(src_raw),
        "dst_ip": socket.inet_ntoa(dst_raw),
        "total_length": total_length,
        "payload": packet[header_length_bytes:total_length],
    }
