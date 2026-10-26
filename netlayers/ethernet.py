import struct

from netlayers.constant import ETH_HEADER_LEN, ETHERTYPE_VLAN, VLAN_ETH_HEADER_LEN
from netlayers.utils import format_mac


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


result =parse_frame(
    b"fGQkc\xcc\x1aF\xf73u\xa8\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\x1aF\xf73u\xa8\n\x00\x00\x02fGQkc\xcc\n\x00\x00\x01"
)

print(result)
