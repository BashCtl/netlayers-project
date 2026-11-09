import socket
from unittest.mock import MagicMock

import pytest

from tools import ping as ping_module


def test_calculate_ping_statistics_with_replies():
    stats = ping_module.calculate_ping_statistics(4, 2, [10.0, 20.0], 100.0)

    assert stats.packets_sent == 4
    assert stats.packets_received == 2
    assert stats.packet_loss == 50.0
    assert stats.min_rtt == 10.0
    assert stats.avg_rtt == 15.0
    assert stats.max_rtt == 20.0
    assert stats.mdev_rtt == 5.0
    assert stats.elapsed_time == 100.0


def test_calculate_ping_statistics_without_packets():
    stats = ping_module.calculate_ping_statistics(0, 0, [], 0.0)

    assert stats.packet_loss == 0.0
    assert stats.min_rtt == stats.avg_rtt == stats.max_rtt == stats.mdev_rtt == 0


def test_receive_echo_reply_returns_matching_reply(monkeypatch):
    monkeypatch.setattr(
        ping_module.time, "monotonic", MagicMock(side_effect=[0, 0.1, 0.2])
    )
    monkeypatch.setattr(
        ping_module,
        "parse_frame",
        lambda data: {
            "ethertype": ping_module.ETHERTYPE_IPV4,
            "payload": b"ip",
        },
    )
    monkeypatch.setattr(
        ping_module,
        "parse_ipv4",
        lambda data: {
            "protocol": ping_module.IP_PROTO_ICMP,
            "payload": b"icmp",
            "src_ip": "192.0.2.1",
            "ttl": 64,
        },
    )
    monkeypatch.setattr(
        ping_module,
        "parse_icmp",
        lambda data: {
            "type": ping_module.ICMP_ECHO_REPLY,
            "code": ping_module.ICMP_CODE_ECHO,
            "identifier": 7,
            "sequence": 1,
        },
    )
    mock_socket = MagicMock()
    mock_socket.recvfrom.return_value = (b"frame", ("", 0, 0, 0, ""))

    reply = ping_module.receive_echo_reply(mock_socket, 7, 1, "192.0.2.1", 0.05, 1.0)

    assert reply.ttl == 64
    assert reply.payload_size == 4
    assert reply.rtt == pytest.approx(150.0)
    assert reply.sequence == 1
    assert reply.dst_ip == "192.0.2.1"


def test_receive_echo_reply_returns_none_on_socket_timeout():
    mock_socket = MagicMock()
    mock_socket.recvfrom.side_effect = socket.timeout

    assert ping_module.receive_echo_reply(
        mock_socket, 7, 1, "192.0.2.1", 0.0, 1.0
    ) is None


def test_ping_reports_unreachable_destination(monkeypatch, capsys):
    monkeypatch.setattr(
        ping_module,
        "find_route",
        MagicMock(side_effect=TimeoutError("no route")),
    )

    ping_module.ping("192.0.2.1", count=1)

    assert capsys.readouterr().out.strip() == "Destination host unreachable"
