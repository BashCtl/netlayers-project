import struct

from netlayers.constant import (
    ETH_HEADER_LEN,
    ETHER_MAX_PAYLOAD,
    ETHER_MIN_PAYLOAD,
    ETHERTYPE_VLAN,
    VLAN_ETH_HEADER_LEN,
)
from netlayers.utils import format_mac, parse_mac


def parse_frame(raw_data: bytes) -> dict:
    if len(raw_data) < ETH_HEADER_LEN:
        raise ValueError("Invalid Ethernet frame length")

    dst_mac, src_mac, ethertype = struct.unpack_from("!6s6sH", raw_data, 0)
    dst_mac = format_mac(dst_mac)
    src_mac = format_mac(src_mac)
    payload = raw_data[ETH_HEADER_LEN:]

    vlan_tci = None
    vlan_id = None
    if ethertype == ETHERTYPE_VLAN:
        if len(raw_data) < VLAN_ETH_HEADER_LEN:
            raise ValueError("Truncated VLAN frame")
        vlan_tci, ethertype = struct.unpack_from("!2H", raw_data, ETH_HEADER_LEN)
        vlan_id = vlan_tci & 0x0FFF
        payload = raw_data[VLAN_ETH_HEADER_LEN:]

    return {
        "dst_mac": dst_mac,
        "src_mac": src_mac,
        "ethertype": ethertype,
        "vlan_id": vlan_id,
        "vlan_tci": vlan_tci,
        "payload": payload,
    }


def build_frame(
    dst_mac: str,
    src_mac: str,
    ethertype: int,
    payload: bytes = b"",
    *,
    pad: bool = False,
) -> bytes:
    if not 0 <= ethertype <= 0xFFFF:
        raise ValueError(f"EtherType out of range: {ethertype}")
    if len(payload) > ETHER_MAX_PAYLOAD:
        raise ValueError("Payload exceeds Ethernet MTU")

    header = struct.pack("!6s6sH", parse_mac(dst_mac), parse_mac(src_mac), ethertype)
    if pad and len(payload) < ETHER_MIN_PAYLOAD:
        payload = payload.ljust(ETHER_MIN_PAYLOAD, b"\x00")
    return header + payload
