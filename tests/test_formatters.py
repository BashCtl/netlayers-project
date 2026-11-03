from netlayers.formatters import (
    FORMATTERS,
    format_arp,
    format_ethernet,
    format_icmp,
    format_ipv4,
    format_tcp,
    format_udp,
    get_tcp_active_flags,
)


def test_format_ethernet_without_vlan():
    eth = {
        "dst_mac": "66:47:51:6b:63:cc",
        "src_mac": "00:11:22:33:44:55",
        "ethertype": 0x0800,
        "vlan_id": None,
        "payload": b"data",
    }

    assert format_ethernet(eth) == (
        "Ethernet frame:\n"
        "Destination MAC: 66:47:51:6b:63:cc\n"
        "Source MAC: 00:11:22:33:44:55\n"
        "Ethertype: IPv4\n"
        "Payload: 4 bytes"
    )


def test_format_ethernet_includes_vlan_id():
    eth = {
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "src_mac": "00:11:22:33:44:55",
        "ethertype": 0x0806,
        "vlan_id": 100,
        "payload": b"",
    }

    assert "VLAN ID: 100" in format_ethernet(eth)


def test_format_icmp_echo_includes_identifier_and_sequence():
    icmp = {
        "type": 8,
        "code": 0,
        "checksum": 1234,
        "identifier": 5,
        "sequence": 9,
        "payload": b"hello",
    }

    assert format_icmp(icmp) == (
        "ICMP packet:\n"
        "Type: Echo Request\n"
        "Code: 0\n"
        "Checksum: 1234\n"
        "Identifier: 5\n"
        "Sequence: 9\n"
        "Payload: 5 bytes"
    )


def test_format_icmp_non_echo_omits_identifier_and_sequence():
    output = format_icmp({"type": 3, "code": 1, "checksum": 42, "payload": b""})

    assert "Type: Destination Unreachable" in output
    assert "Identifier:" not in output
    assert "Sequence:" not in output
    assert output.endswith("Payload: 0 bytes")


def test_format_arp():
    arp = {
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "opcode": 1,
        "sender_mac": "00:11:22:33:44:55",
        "sender_ip": "192.168.1.1",
        "target_mac": "00:00:00:00:00:00",
        "target_ip": "192.168.1.2",
    }

    assert format_arp(arp) == (
        "ARP packet:\n"
        "Hardware type: 1\n"
        "Protocol type: IPv4\n"
        "Opcode: REQUEST\n"
        "Sender MAC: 00:11:22:33:44:55\n"
        "Sender IP: 192.168.1.1\n"
        "Target MAC: 00:00:00:00:00:00\n"
        "Target IP: 192.168.1.2\n"
    )


def test_format_ipv4_and_unknown_protocol():
    ip = {
        "version": 4,
        "ihl": 5,
        "ttl": 64,
        "protocol": 99,
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "total_length": 23,
        "payload": b"abc",
    }

    assert format_ipv4(ip) == (
        "IPv4 Packet:\n"
        "Version: 4\n"
        "IHL: 5\n"
        "TTL: 64\n"
        "Protocol: Unknown\n"
        "Source IP: 192.168.1.1\n"
        "Destination IP: 192.168.1.2\n"
        "Total length: 23 bytes\n"
        "Payload: 3 bytes\n"
    )


def test_get_tcp_active_flags_returns_set_bits_in_flag_order():
    assert get_tcp_active_flags(0x12) == ["SYN", "ACK"]
    assert get_tcp_active_flags(0) == []


def test_format_tcp():
    tcp = {
        "src_port": 12345,
        "dst_port": 443,
        "sequence_num": 100,
        "ack_num": 200,
        "header_length": 20,
        "flags": 0x12,
        "window_size": 4096,
        "checksum": 65535,
        "urgent_pointer": 0,
        "payload": b"request",
    }

    assert format_tcp(tcp) == (
        "TCP Segment:\n"
        "Source port: 12345\n"
        "Destination port: 443\n"
        "Sequence number: 100\n"
        "Acknowledgment number: 200\n"
        "Header length: 20 bytes\n"
        "Flags: ['SYN', 'ACK']\n"
        "Window size: 4096 bytes\n"
        "Checksum: 65535\n"
        "Urgent pointer: 0\n"
        "Payload: 7 bytes\n"
    )


def test_format_udp():
    udp = {
        "src_port": 53,
        "dst_port": 53000,
        "length": 11,
        "checksum": 456,
        "payload": b"dns",
    }

    assert format_udp(udp) == (
        "UDP datagram:\n"
        "Source port: 53\n"
        "Destination port: 53000\n"
        "Length: 11 bytes\n"
        "Checksum: 456\n"
        "Payload: 3 bytes\n"
    )


def test_formatter_registry_maps_layer_names_to_formatters():
    assert FORMATTERS == {
        "ethernet": format_ethernet,
        "ipv4": format_ipv4,
        "arp": format_arp,
        "icmp": format_icmp,
        "tcp": format_tcp,
        "udp": format_udp,
    }
