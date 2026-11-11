import argparse
import os
import socket
import struct
import time
from dataclasses import dataclass

from netlayers.constant import (
    ETHERTYPE_IPV4,
    ICMP_CODE_ECHO,
    ICMP_CODE_TTL_EXCEEDED,
    ICMP_DEST_UNREACHABLE,
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    ICMP_TIME_EXCEEDED,
    IP_PROTO_ICMP,
    IPV4_MIN_HEADER_LENGTH,
    PROBES_PER_HOP,
    RECV_BUFFER_SIZE,
)
from netlayers.ethernet import build_frame, parse_frame
from netlayers.icmp import build_icmp_echo_request, parse_icmp
from netlayers.ipv4 import build_ipv4_packet, parse_ipv4
from netlayers.network import find_route, get_local_ip, resolve_target_mac
from netlayers.utils import format_mac, ipv4_address, positive_float, positive_int

UNREACHABLE_MARKS = {
    0: "!N",
    1: "!H",
    2: "!P",
    3: "!",
    4: "!F",
    9: "!X",
    10: "!X",
    13: "!X",
}


@dataclass(frozen=True)
class ProbeResult:
    ip: str
    rtt: float
    mark: str = ""


def receive_icmp_message(
    sock: socket.socket, deadline: float
) -> tuple[dict, dict, float] | None:

    while True:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return None

        sock.settimeout(remaining)

        try:
            data, addr = sock.recvfrom(RECV_BUFFER_SIZE)
            recv_at = time.monotonic()
        except socket.timeout:
            return None

        if addr[2] == socket.PACKET_OUTGOING:
            continue

        try:
            frame = parse_frame(data)
        except ValueError:
            continue

        if frame["ethertype"] != ETHERTYPE_IPV4:
            continue

        try:
            ip_reply = parse_ipv4(frame["payload"])
        except ValueError:
            continue

        if ip_reply["protocol"] != IP_PROTO_ICMP:
            continue

        try:
            icmp = parse_icmp(ip_reply["payload"])
        except ValueError:
            continue

        return ip_reply, icmp, recv_at


def is_echo_reply_to_probe(
    ip_reply: dict,
    icmp: dict,
    identifier: int,
    sequence: int,
    dst_ip: str,
) -> bool:
    return (
        icmp["type"] == ICMP_ECHO_REPLY
        and icmp["code"] == ICMP_CODE_ECHO
        and icmp["identifier"] == identifier
        and icmp["sequence"] == sequence
        and ip_reply["src_ip"] == dst_ip
    )


def extract_probe_ids(payload: bytes) -> tuple[int, int] | None:
    if len(payload) < IPV4_MIN_HEADER_LENGTH:
        return None
    version_ihl = payload[0]

    if version_ihl >> 4 != 4:
        return None
    header_len = (version_ihl & 0x0F) * 4

    if header_len < IPV4_MIN_HEADER_LENGTH:
        return None
    
    if len(payload) < header_len + 8:
        return None
    
    if payload[9] != IP_PROTO_ICMP:
        return None
    
    if payload[header_len] != ICMP_ECHO_REQUEST:
        return None
    
    return struct.unpack_from("!HH", payload, header_len + 4)


def is_route_reply_to_probe(icmp: dict, identifier: int, sequence: int) -> bool:
    if icmp["type"] not in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACHABLE):
        return False
    
    if icmp["type"] == ICMP_TIME_EXCEEDED and icmp["code"] != ICMP_CODE_TTL_EXCEEDED:
        return False
    
    ids = extract_probe_ids(icmp["payload"])

    return ids == (identifier, sequence)


def print_hop(ttl: int, hop_results: list[ProbeResult]) -> None:
    ips = [r.ip for r in hop_results if r is not None]

    if not ips:
        print(f"{ttl:2}  " + "  ".join("*" for _ in hop_results))
        return
    
    times = [
        f"{r.rtt:.2f} ms {r.mark}".rstrip() if r is not None else "*"
        for r in hop_results
    ]

    print(f"{ttl:2}  {ips[0]:<15}  " + "  ".join(times))


def traceroute(dst_ip: str, max_hops: int = 30, timeout: float = 1.0) -> None:
    if not 1 <= max_hops <= 255:
        raise ValueError("max_hops must be between 1 and 255")

    try:
        interface, gateway = find_route(dst_ip)
        next_hop = gateway or dst_ip

        with socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(socket.ETH_P_ALL),
        ) as sock:
            
            sock.bind((interface, 0))
            _, _, _, _, hwaddr = sock.getsockname()
            src_mac = format_mac(hwaddr)
            src_ip = get_local_ip(dst_ip)
            dst_mac = resolve_target_mac(sock, src_mac, src_ip, next_hop, timeout)
            identifier = os.getpid() & 0xFFFF

            print(f"traceroute to {dst_ip}, {max_hops} hops max")

            try:
                for ttl in range(1, max_hops + 1):
                    stop = False

                    hop_results = []
                    for probe in range(PROBES_PER_HOP):
                        result = None
                        sequence = (ttl - 1) * PROBES_PER_HOP + probe + 1
                        icmp_message = build_icmp_echo_request(
                            identifier=identifier,
                            sequence=sequence,
                            payload=b"X" * 56,
                        )
                        ipv4_packet = build_ipv4_packet(
                            src_ip,
                            dst_ip,
                            IP_PROTO_ICMP,
                            payload=icmp_message,
                            ttl=ttl,
                        )
                        ethernet_frame = build_frame(
                            dst_mac,
                            src_mac,
                            ETHERTYPE_IPV4,
                            payload=ipv4_packet,
                        )

                        sent_at = time.monotonic()
                        deadline = sent_at + timeout
                        sock.send(ethernet_frame)

                        while True:
                            recv_result = receive_icmp_message(sock, deadline)

                            if recv_result is None:
                                break

                            ip_reply, icmp, recv_at = recv_result

                            if is_echo_reply_to_probe(
                                ip_reply, icmp, identifier, sequence, dst_ip
                            ):
                                rtt = (recv_at - sent_at) * 1000
                                result = ProbeResult(ip_reply["src_ip"], rtt, "")
                                stop = True
                                break

                            if is_route_reply_to_probe(icmp, identifier, sequence):
                                rtt = (recv_at - sent_at) * 1000
                                mark = ""

                                if icmp["type"] == ICMP_DEST_UNREACHABLE:
                                    mark = UNREACHABLE_MARKS.get(icmp["code"], "!?")
                                    stop = True

                                result = ProbeResult(ip_reply["src_ip"], rtt, mark)
                                break

                        hop_results.append(result)
                        
                    print_hop(ttl, hop_results)

                    if stop:
                        break
            except KeyboardInterrupt:
                pass

    except TimeoutError:
        print("Destination host unreachable")
    except PermissionError:
        print("Run with sudo")
    except OSError as e:
        print(f"Network is unreachable: {e}")
    except ValueError as e:
        print(f"Value error: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Traceroute - print the route packets trace to destination IPv4"
    )
    parser.add_argument(
        "destination",
        type=ipv4_address,
        help="Target IPv4 address",
    )
    parser.add_argument(
        "--max-hops",
        type=positive_int,
        default=30,
        help="Max number of  hops.",
    )
    parser.add_argument(
        "--timeout", type=positive_float, default=1.0, help="Timeout in seconds"
    )

    args = parser.parse_args()

    try:
        traceroute(
            dst_ip=args.destination,
            max_hops=args.max_hops,
            timeout=args.timeout,
        )
    except ValueError as e:
        parser.error(str(e))


if __name__ == "__main__":
    main()
