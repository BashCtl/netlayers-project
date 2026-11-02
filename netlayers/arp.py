import socket
import struct

from netlayers.constant import ETHERTYPE_IPV4
from netlayers.utils import format_mac


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
