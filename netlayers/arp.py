import ipaddress
import socket
import struct

from netlayers.constant import (
    ARP_HLEN_ETHERNET,
    ARP_HTYPE_ETHERNET,
    ARP_PLEN_IPV4,
    ARP_REPLY,
    ARP_REQUEST,
    ETHERTYPE_IPV4,
)
from netlayers.utils import format_mac, parse_mac


def parse_arp(ether_payload: bytes):
    if len(ether_payload) < 28:
        raise ValueError("Invalid ARP payload")
    (
        hardware_type,
        protocol_type,
        hlen,
        plen,
        opcode,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    ) = struct.unpack_from("!HHBBH6s4s6s4s", ether_payload)

    if hardware_type != 1:
        raise ValueError(f"Unsupported ARP hardware type: {hardware_type}")
    if protocol_type != ETHERTYPE_IPV4:
        raise ValueError(f"Unsupported ARP protocol type: 0x{protocol_type:04x}")
    if hlen != 6 or plen != 4:
        raise ValueError(f"Unexpected ARP address lengths: {hlen}/{plen}")

    return {
        "hardware_type": hardware_type,
        "protocol_type": protocol_type,
        "opcode": opcode,
        "sender_mac": format_mac(sender_mac),
        "sender_ip": socket.inet_ntoa(sender_ip),
        "target_mac": format_mac(target_mac),
        "target_ip": socket.inet_ntoa(target_ip),
    }


def build_arp(
    opcode: int,
    sender_mac: str,
    sender_ip: str,
    target_mac: str,
    target_ip: str,
) -> bytes:

    if opcode not in (ARP_REPLY, ARP_REQUEST):
        raise ValueError("Invalid 'opcode'")

    sender_mac_bytes = parse_mac(sender_mac)
    target_mac_bytes = parse_mac(target_mac)

    sender_ip_bytes = ipaddress.IPv4Address(sender_ip).packed
    target_ip_bytes = ipaddress.IPv4Address(target_ip).packed

    arp_payload = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HTYPE_ETHERNET,
        ETHERTYPE_IPV4,
        ARP_HLEN_ETHERNET,
        ARP_PLEN_IPV4,
        opcode,
        sender_mac_bytes,
        sender_ip_bytes,
        target_mac_bytes,
        target_ip_bytes,
    )
    return arp_payload
