import io
import socket
from unittest.mock import MagicMock

import pytest

from netlayers.arp import build_arp
from netlayers.constant import ARP_REPLY, ETHERTYPE_ARP
from netlayers.ethernet import build_frame
from netlayers.network import find_route, get_local_ip, resolve_target_mac


def _route_line(interface, destination, gateway, metric, mask, flags=1):
    def route_hex(address):
        return f"{socket.htonl(int.from_bytes(socket.inet_aton(address), 'big')):08X}"

    return (
        f"{interface} {route_hex(destination)} {route_hex(gateway)} "
        f"{flags:04X} 0 0 {metric} {route_hex(mask)} 0 0 0\n"
    )


def test_get_local_ip_returns_selected_address(monkeypatch):
    mock_socket = MagicMock()
    mock_socket.__enter__.return_value = mock_socket
    mock_socket.getsockname.return_value = ("192.168.1.10", 12345)
    socket_factory = MagicMock(return_value=mock_socket)
    monkeypatch.setattr(socket, "socket", socket_factory)

    assert get_local_ip("8.8.8.8") == "192.168.1.10"
    socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    mock_socket.connect.assert_called_once_with(("8.8.8.8", 9))


def test_find_route_prefers_most_specific_route(monkeypatch):
    routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
    routes += _route_line("default", "0.0.0.0", "192.168.1.1", 1, "0.0.0.0")
    routes += _route_line("lan0", "192.168.1.0", "0.0.0.0", 10, "255.255.255.0")
    monkeypatch.setattr("builtins.open", lambda *args: io.StringIO(routes))

    assert find_route("192.168.1.42") == ("lan0", None)


def test_find_route_unreachable_destination(monkeypatch):
    routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
    monkeypatch.setattr("builtins.open", lambda *args: io.StringIO(routes))
    with pytest.raises(OSError, match="Network is unreachable"):
        find_route("10.0.0.1")


def test_resolve_target_mac_returns_matching_reply_and_restores_timeout():
    payload = build_arp(
        opcode=ARP_REPLY,
        sender_mac="aa:bb:cc:dd:ee:ff",
        sender_ip="192.168.1.20",
        target_mac="00:11:22:33:44:55",
        target_ip="192.168.1.10",
    )
    frame = build_frame(
        dst_mac="00:11:22:33:44:55",
        src_mac="aa:bb:cc:dd:ee:ff",
        ethertype=ETHERTYPE_ARP,
        payload=payload,
    )

    mock_socket = MagicMock()
    mock_socket.gettimeout.return_value = 5.0
    mock_socket.recvfrom.return_value = (frame, ("", 0, 0, 0, ""))
    result = resolve_target_mac(
        mock_socket,
        "00:11:22:33:44:55",
        "192.168.1.10",
        "192.168.1.20",
    )

    assert result == "aa:bb:cc:dd:ee:ff"
    mock_socket.send.assert_called_once()
    mock_socket.settimeout.assert_called()
    assert mock_socket.settimeout.call_args_list[-1].args == (5.0,)


def test_resolve_target_mac_timeout_restores_socket_timeout():
    mock_socket = MagicMock()
    mock_socket.gettimeout.return_value = 5.0
    mock_socket.recvfrom.side_effect = socket.timeout
    with pytest.raises(TimeoutError, match="No ARP reply"):
        resolve_target_mac(
            mock_socket,
            "00:11:22:33:44:55",
            "192.168.1.10",
            "192.168.1.20",
        )
    assert mock_socket.settimeout.call_args_list[-1].args == (5.0,)
