import ipaddress
import socket
import struct

from netlayers.checksum import internet_checksum
from netlayers.constant import (
    IP_VERSION_4,
    IPV4_FLAG_DF,
    IPV4_MAX_LENGTH,
    IPV4_MIN_HEADER_LENGTH,
    IPV4_MIN_IHL,
    IPV4_TOS_DEFAULT,
    LOWER_NIBBLE_MASK,
)
from netlayers.utils import validate_uint


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


def _pack_ipv4(
    version_ihl: int,
    tos: int,
    total_length: int,
    identification: int,
    flags_frag: int,
    ttl: int,
    protocol: int,
    checksum: int,
    src_ip: bytes,
    dst_ip: bytes,
) -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        checksum,
        src_ip,
        dst_ip,
    )


def build_ipv4_packet(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload: bytes = b"",
    *,
    ttl: int = 64,
    identification: int = 0,
    dont_fragment: bool = True,
) -> bytes:
    validate_uint(protocol, 8, "Protocol")
    validate_uint(ttl, 8, "TTL")
    validate_uint(identification, 16, "Identification")

    total_length = IPV4_MIN_HEADER_LENGTH + len(payload)

    if total_length > IPV4_MAX_LENGTH:
        raise ValueError("IPv4 packet is too large")
    if not isinstance(payload, bytes):
        raise ValueError("Payload must be bytes")

    version_ihl = (IP_VERSION_4 << 4) | IPV4_MIN_IHL
    flags_frag = IPV4_FLAG_DF if dont_fragment else 0

    src_ip_bytes = ipaddress.IPv4Address(src_ip).packed
    dst_ip_bytes = ipaddress.IPv4Address(dst_ip).packed

    header_no_checksum = _pack_ipv4(
        version_ihl,
        IPV4_TOS_DEFAULT,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        0,
        src_ip_bytes,
        dst_ip_bytes,
    )

    checksum = internet_checksum(header_no_checksum)
    header = bytearray(header_no_checksum)
    header[10:12] = struct.pack("!H", checksum)

    return bytes(header) + payload
