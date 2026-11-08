import argparse
import math
import os
import socket
import time
from dataclasses import dataclass

from netlayers.constant import (
    ETHERTYPE_IPV4,
    ICMP_CODE_ECHO,
    ICMP_ECHO_REPLY,
    IP_PROTO_ICMP,
    PING_INTERVAL,
    RECV_BUFFER_SIZE,
)
from netlayers.ethernet import build_frame, parse_frame
from netlayers.icmp import build_icmp_echo_request, parse_icmp
from netlayers.ipv4 import build_ipv4_packet, parse_ipv4
from netlayers.network import find_route, get_local_ip, resolve_target_mac
from netlayers.utils import format_mac, ipv4_address, positive_float, positive_int


@dataclass
class PingStatistics:
    packets_sent: int
    packets_received: int
    packet_loss: float
    min_rtt: float
    avg_rtt: float
    max_rtt: float
    mdev_rtt: float
    elapsed_time: float


@dataclass
class EchoReply:
    ttl: int
    payload_size: int
    rtt: float
    sequence: int
    dst_ip: str


def calculate_ping_statistics(
    packets_sent: int,
    packets_received: int,
    rtts: list,
    elapsed_time: float,
) -> PingStatistics:
    packet_loss = (
        ((packets_sent - packets_received) / packets_sent) * 100
        if packets_sent
        else 0.0
    )
    min_rtt = min(rtts) if rtts else 0
    avg_rtt = sum(rtts) / len(rtts) if rtts else 0
    max_rtt = max(rtts) if rtts else 0
    mdev_rtt = (
        math.sqrt(sum((rtt - avg_rtt) ** 2 for rtt in rtts) / len(rtts)) if rtts else 0
    )

    return PingStatistics(
        packets_sent,
        packets_received,
        packet_loss,
        min_rtt,
        avg_rtt,
        max_rtt,
        mdev_rtt,
        elapsed_time,
    )


def print_ping_statistics(
    dst_ip,
    stats: PingStatistics,
) -> None:

    print(f"\n--- {dst_ip} ping statistics ---")
    print(
        f"{stats.packets_sent} packets transmitted, "
        f"{stats.packets_received} received, "
        f"{stats.packet_loss:.1f}% packet loss, "
        f"time {stats.elapsed_time:.0f}ms"
    )
    if stats.packets_received:
        print(
            f"rtt min/avg/max/mdev = {stats.min_rtt:.3f}/{stats.avg_rtt:.3f}/"
            f"{stats.max_rtt:.3f}/{stats.mdev_rtt:.3f} ms"
        )


def receive_echo_reply(
    sock,
    identifier: int,
    sequence: int,
    dst_ip: str,
    sent_at: float,
    timeout: float,
) -> None | EchoReply:
    deadline = time.monotonic() + timeout

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

        if icmp["type"] != ICMP_ECHO_REPLY:
            continue

        if icmp["code"] != ICMP_CODE_ECHO:
            continue

        if icmp["identifier"] != identifier or icmp["sequence"] != sequence:
            continue

        if ip_reply["src_ip"] != dst_ip:
            continue

        rtt = (recv_at - sent_at) * 1000
        return EchoReply(
            ttl=ip_reply["ttl"],
            payload_size=len(ip_reply["payload"]),
            rtt=rtt,
            sequence=sequence,
            dst_ip=dst_ip,
        )


def print_echo_reply(reply: EchoReply) -> None:
    print(
        f"{reply.payload_size} bytes from {reply.dst_ip}: "
        f"icmp_seq={reply.sequence} ttl={reply.ttl} time={reply.rtt:.2f} ms"
    )


def ping(dst_ip: str, count: int = 4, timeout: float = 2.0):
    try:
        interface, gateway = find_route(dst_ip)
        next_hop = gateway or dst_ip
        with socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(socket.ETH_P_ALL)
        ) as sock:
            sock.bind((interface, 0))

            _, _, _, _, hwaddr = sock.getsockname()
            src_mac = format_mac(hwaddr)
            src_ip = get_local_ip(dst_ip)
            dst_mac = resolve_target_mac(sock, src_mac, src_ip, next_hop, timeout)

            identifier = os.getpid() & 0xFFFF

            packets_sent = 0
            packets_received = 0
            rtts = []
            start_time = time.monotonic()
            try:
                for sequence in range(1, count + 1):
                    icmp_message = build_icmp_echo_request(
                        identifier=identifier, sequence=sequence, payload=b"X" * 56
                    )
                    ipv4_packet = build_ipv4_packet(
                        src_ip, dst_ip, IP_PROTO_ICMP, payload=icmp_message
                    )
                    ethernet_frame = build_frame(
                        dst_mac, src_mac, ETHERTYPE_IPV4, payload=ipv4_packet
                    )

                    sent_at = time.monotonic()
                    sock.send(ethernet_frame)
                    packets_sent += 1

                    echo_reply = receive_echo_reply(
                        sock, identifier, sequence, dst_ip, sent_at, timeout
                    )
                    if echo_reply is None:
                        print(f"Request timeout for icmp_seq={sequence}")
                    else:
                        packets_received += 1
                        rtts.append(echo_reply.rtt)
                        print_echo_reply(echo_reply)
                    elapsed = time.monotonic() - sent_at
                    if sequence < count and elapsed < PING_INTERVAL:
                        time.sleep(PING_INTERVAL - elapsed)

            except KeyboardInterrupt:
                pass

            elapsed_time = (time.monotonic() - start_time) * 1000
            statistics = calculate_ping_statistics(
                packets_sent, packets_received, rtts, elapsed_time
            )
            print_ping_statistics(
                dst_ip,
                statistics,
            )
    except TimeoutError:
        print("Destination host unreachable")
    except PermissionError:
        print("Run with sudo")
    except OSError as e:
        print(f"Network is unreachable: {e}")
    except ValueError as e:
        print(f"Value error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Send ICMP echo requests to network hosts"
    )
    parser.add_argument(
        "destination",
        type=ipv4_address,
        help="Target IPv4 address",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=positive_int,
        default=4,
        help="Number of echo requests to send",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=2.0,
        help="Timeout in seconds for each echo reply",
    )

    args = parser.parse_args()

    try:
        ping(
            dst_ip=args.destination,
            count=args.count,
            timeout=args.timeout,
        )
    except ValueError as e:
        parser.error(str(e))


if __name__ == "__main__":
    main()
