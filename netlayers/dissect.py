from typing import Any

from netlayers.arp import parse_arp
from netlayers.constant import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    IP_PROTO_ICMP,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
)
from netlayers.ethernet import parse_frame
from netlayers.icmp import parse_icmp
from netlayers.ipv4 import parse_ipv4
from netlayers.tcp import parse_tcp
from netlayers.udp import parse_udp

ETHERTYPE_PARSERS = {
    ETHERTYPE_IPV4: ("ipv4", parse_ipv4),
    ETHERTYPE_ARP: ("arp", parse_arp),
}
IP_PROTO_PARSERS = {
    IP_PROTO_ICMP: ("icmp", parse_icmp),
    IP_PROTO_TCP: ("tcp", parse_tcp),
    IP_PROTO_UDP: ("udp", parse_udp),
}


def dissect(raw_data: bytes) -> dict[str, Any]:
    layers: dict[str, Any] = {"ethernet": parse_frame(raw_data)}
    ethernet = layers["ethernet"]

    parser_entry = ETHERTYPE_PARSERS.get(ethernet["ethertype"])
    if parser_entry is None:
        return layers

    name, parser = parser_entry
    try:
        layers[name] = parser(ethernet["payload"])
    except ValueError as e:
        layers["error"] = str(e)
        return layers

    if name == "ipv4":
        proto_entry = IP_PROTO_PARSERS.get(layers["ipv4"]["protocol"])
        if proto_entry is not None:
            proto_name, proto_parser = proto_entry
            try:
                layers[proto_name] = proto_parser(layers["ipv4"]["payload"])
            except ValueError as e:
                layers["error"] = str(e)
    return layers
