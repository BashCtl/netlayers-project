import ipaddress
import socket
import time

from netlayers.arp import build_arp, parse_arp
from netlayers.constant import (
    ARP_REPLY,
    ARP_REQUEST,
    BROADCAST_MAC,
    ETHERTYPE_ARP,
    RECV_BUFFER_SIZE,
    RTF_UP,
    ZERO_MAC,
)
from netlayers.ethernet import build_frame, parse_frame


def get_local_ip(dst_ip: str) -> str:
    """Return the local IP address the kernel would use to reach dst_ip.

    Args:
        dst_ip (str): Destination IP address in string form.

    Returns:
        str: Local IPv4 address.

    Raises:
        OSError: If there is no route to dst_ip.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((dst_ip, 9))
        return sock.getsockname()[0]


def find_route(dst_ip: str) -> tuple[str, str | None]:
    """It reads /proc/net/route, returns (interface, gateway)

    Args:
        dst_ip (str): Destination IP address

    Raises:
        OSError: If no route can be found

    Returns:
        tuple[str, str | None]: Network interface and getway, gateway is None for directly connected networks.
    """

    dst_ip_int = int(ipaddress.IPv4Address(dst_ip))
    with open("/proc/net/route", "r") as file:
        next(file)
        routes = []
        for line in file:
            fields = line.strip().split()

            if len(fields) < 8:
                continue

            if not int(fields[3], 16) & RTF_UP:
                continue

            interface = fields[0]
            dest_int = socket.ntohl(int(fields[1], 16))
            metric = int(fields[6])
            mask_int = socket.ntohl(int(fields[7], 16))
            masked_ip = dst_ip_int & mask_int

            if masked_ip == dest_int:
                gw_int = socket.ntohl(int(fields[2], 16))
                gateway = str(ipaddress.IPv4Address(gw_int)) if gw_int else None
                routes.append(
                    {
                        "interface": interface,
                        "gateway": gateway,
                        "metric": metric,
                        "mask": mask_int,
                    }
                )

        if not routes:
            raise OSError(f"Network is unreachable: {dst_ip}")

        result = max(routes, key=lambda route: (route["mask"], -route["metric"]))
        return result["interface"], result["gateway"]


def resolve_target_mac(
    s: socket.socket,
    src_mac: str,
    src_ip: str,
    target_ip: str,
    timeout: float = 2.0,
) -> str:

    arp_payload = build_arp(
        opcode=ARP_REQUEST,
        sender_mac=src_mac,
        sender_ip=src_ip,
        target_mac=ZERO_MAC,
        target_ip=target_ip,
    )
    ether_frame = build_frame(
        dst_mac=BROADCAST_MAC,
        src_mac=src_mac,
        ethertype=ETHERTYPE_ARP,
        payload=arp_payload,
    )

    previous_timeout = s.gettimeout()

    try:
        deadline = time.monotonic() + timeout
        s.send(ether_frame)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timeout ocurred resolving target MAC addresss")

            s.settimeout(remaining)
            frame, addr = s.recvfrom(RECV_BUFFER_SIZE)

            if addr[2] == socket.PACKET_OUTGOING:
                continue

            try:
                parsed_frame = parse_frame(frame)

                if parsed_frame["ethertype"] != ETHERTYPE_ARP:
                    continue

                parsed_arp = parse_arp(parsed_frame["payload"])
            except ValueError:
                continue

            if (
                parsed_arp["opcode"] == ARP_REPLY
                and parsed_arp["sender_ip"] == target_ip
            ):
                return parsed_arp["sender_mac"]
    except socket.timeout as e:
        raise TimeoutError(f"No ARP reply from '{target_ip}'") from e
    finally:
        s.settimeout(previous_timeout)



