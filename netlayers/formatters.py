from netlayers.constant import (
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
)

ETHERTYPES_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}

IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    4: "IPv4",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

ARP_OPCODES = {
    1: "REQUEST",
    2: "REPLY",
}

ARP_PROTOCOL_TYPES = {
    0x0800: "IPv4",
    0x86DD: "IPv6",
}

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    15: "Information Request",
    16: "Information Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
}

TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


def format_ethernet(eth: dict) -> str:
    result = []
    result.append("Ethernet frame:")
    result.append(f"Destination MAC: {eth['dst_mac']}")
    result.append(f"Source MAC: {eth['src_mac']}")
    result.append(f"Ethertype: {ETHERTYPES_NAMES[eth['ethertype']]}")
    if eth["vlan_id"] is not None:
        result.append(f"VLAN ID: {eth['vlan_id']}")
    result.append(f"Payload: {len(eth['payload'])} bytes")

    return "\n".join(result)


def format_icmp(icmp: dict) -> str:
    result = []
    result.append("ICMP packet:")
    result.append(f"Type: {ICMP_TYPES.get(icmp['type'])}")
    result.append(f"Code: {icmp['code']}")
    result.append(f"Checksum: {icmp['checksum']}")
    if icmp["type"] in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST):
        result.append(f"Identifier: {icmp['identifier']}")
        result.append(f"Sequence: {icmp['sequence']}")
    result.append(f"Payload: {len(icmp['payload'])} bytes")
    return "\n".join(result)


def format_arp(arp: dict) -> str:
    return (
        "ARP packet:\n"
        f"Hardware type: {arp['hardware_type']}\n"
        f"Protocol type: {ARP_PROTOCOL_TYPES.get(arp['protocol_type'])}\n"
        f"Opcode: {ARP_OPCODES.get(arp['opcode'])}\n"
        f"Sender MAC: {arp['sender_mac']}\n"
        f"Sender IP: {arp['sender_ip']}\n"
        f"Target MAC: {arp['target_mac']}\n"
        f"Target IP: {arp['target_ip']}\n"
    )


def format_ipv4(ip: dict) -> str:
    return (
        f"IPv4 Packet:\n"
        f"Version: {ip['version']}\n"
        f"IHL: {ip['ihl']}\n"
        f"TTL: {ip['ttl']}\n"
        f"Protocol: {IP_PROTOCOLS.get(ip['protocol'], "Unknown")}\n"
        f"Source IP: {ip['src_ip']}\n"
        f"Destination IP: {ip['dst_ip']}\n"
        f"Total length: {ip['total_length']} bytes\n"
        f"Payload: {len(ip['payload'])} bytes\n"
    )


def get_tcp_active_flags(flags: int) -> list[str]:
    return [name for mask, name in TCP_FLAGS.items() if flags & mask]


def format_tcp(tcp: dict) -> str:
    return (
        "TCP Segment:\n"
        f"Source port: {tcp['src_port']}\n"
        f"Destination port: {tcp['dst_port']}\n"
        f"Sequence number: {tcp['sequence_num']}\n"
        f"Acknowledgment number: {tcp['ack_num']}\n"
        f"Header length: {tcp['header_length']} bytes\n"
        f"Flags: {get_tcp_active_flags(tcp['flags'])}\n"
        f"Window size: {tcp['window_size']} bytes\n"
        f"Checksum: {tcp['checksum']}\n"
        f"Urgent pointer: {tcp['urgent_pointer']}\n"
        f"Payload: {len(tcp['payload'])} bytes\n"
    )


def format_udp(udp: dict) -> str:
    return (
        "UDP datagram:\n"
        f"Source port: {udp['src_port']}\n"
        f"Destination port: {udp['dst_port']}\n"
        f"Length: {udp['length']} bytes\n"
        f"Checksum: {udp['checksum']}\n"
        f"Payload: {len(udp['payload'])} bytes\n"
    )


FORMATTERS = {
    "ethernet": format_ethernet,
    "ipv4": format_ipv4,
    "arp": format_arp,
    "icmp": format_icmp,
    "tcp": format_tcp,
    "udp": format_udp,
}
