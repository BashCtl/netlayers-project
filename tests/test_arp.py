import ipaddress
import struct

import pytest

from netlayers.arp import build_arp, parse_arp
from netlayers.constant import (
    ARP_HLEN_ETHERNET,
    ARP_HTYPE_ETHERNET,
    ARP_PLEN_IPV4,
    ARP_REPLY,
    ARP_REQUEST,
    ETHERTYPE_IPV4,
)

# Valid ARP Ethernet frame
ETHER_FRAME = bytes.fromhex(
    "ffffffffffff9660f528217508060001080006040001"
    "9660f52821750a0000010000000000000a000002"
)

# ARP payload starts after the 14-byte Ethernet header
ARP_PAYLOAD = ETHER_FRAME[14:]


@pytest.fixture
def arp_values():
    return {
        "sender_mac": "00:11:22:33:44:55",
        "sender_ip": "192.168.1.10",
        "target_mac": "AA:BB:CC:DD:EE:FF",
        "target_ip": "192.168.1.20",
    }


def test_parse_valid_arp_payload():
    result = parse_arp(ARP_PAYLOAD)

    assert result == {
        "hardware_type": 1,
        "protocol_type": 0x0800,
        "opcode": 1,
        "sender_mac": "96:60:f5:28:21:75",
        "sender_ip": "10.0.0.1",
        "target_mac": "00:00:00:00:00:00",
        "target_ip": "10.0.0.2",
    }


def test_parse_arp_payload_too_short():
    with pytest.raises(ValueError, match="Invalid ARP payload"):
        parse_arp(b"\x00" * 27)


def test_parse_unsupported_hardware_type():
    payload = bytearray(ARP_PAYLOAD)
    payload[1] = 2

    with pytest.raises(ValueError, match="Unsupported ARP hardware type: 2"):
        parse_arp(bytes(payload))


def test_parse_unsupported_protocol_type():
    payload = bytearray(ARP_PAYLOAD)
    payload[3] = 1  # Change protocol type from 0x0800 to 0x0801

    with pytest.raises(ValueError, match="Unsupported ARP protocol type: 0x0801"):
        parse_arp(bytes(payload))


def test_parse_unexpected_hardware_address_length():
    payload = bytearray(ARP_PAYLOAD)
    payload[4] = 5

    with pytest.raises(ValueError, match="Unexpected ARP address lengths: 5/4"):
        parse_arp(bytes(payload))


def test_parse_unexpected_protocol_address_length():
    payload = bytearray(ARP_PAYLOAD)
    payload[5] = 3

    with pytest.raises(ValueError, match="Unexpected ARP address lengths: 6/3"):
        parse_arp(bytes(payload))


def test_parse_arp_request_opcode():
    result = parse_arp(ARP_PAYLOAD)

    assert result["opcode"] == 1


def test_parse_arp_reply_opcode():
    payload = bytearray(ARP_PAYLOAD)
    payload[7] = 2  # ARP opcode is at bytes 6-7

    result = parse_arp(bytes(payload))

    assert result["opcode"] == 2


@pytest.mark.parametrize("opcode", [ARP_REQUEST, ARP_REPLY])
def test_build_arp_valid_packet(opcode, arp_values):
    packet = build_arp(opcode, **arp_values)

    assert isinstance(packet, bytes)
    assert len(packet) == 28


@pytest.mark.parametrize("opcode", [ARP_REQUEST, ARP_REPLY])
def test_build_arp_packet_structure(opcode, arp_values):
    packet = build_arp(opcode, **arp_values)

    unpacked = struct.unpack("!HHBBH6s4s6s4s", packet)

    assert unpacked[0] == ARP_HTYPE_ETHERNET
    assert unpacked[1] == ETHERTYPE_IPV4
    assert unpacked[2] == ARP_HLEN_ETHERNET
    assert unpacked[3] == ARP_PLEN_IPV4
    assert unpacked[4] == opcode


def test_build_arp_sender_addresses(arp_values):
    packet = build_arp(ARP_REQUEST, **arp_values)

    unpacked = struct.unpack("!HHBBH6s4s6s4s", packet)

    assert unpacked[5] == bytes.fromhex("001122334455")
    assert unpacked[6] == ipaddress.IPv4Address("192.168.1.10").packed


def test_build_arp_target_addresses(arp_values):
    packet = build_arp(ARP_REPLY, **arp_values)

    unpacked = struct.unpack("!HHBBH6s4s6s4s", packet)

    assert unpacked[7] == bytes.fromhex("AABBCCDDEEFF")
    assert unpacked[8] == ipaddress.IPv4Address("192.168.1.20").packed


def test_build_arp_invalid_opcode(arp_values):
    with pytest.raises(ValueError, match="Invalid 'opcode'"):
        build_arp(99, **arp_values)


@pytest.mark.parametrize(
    "invalid_mac",
    [
        "invalid",
        "00:11:22:33:44",
        "00:11:22:33:44:55:66",
        "00:11:22:33:44:GG",
        "",
    ],
)
def test_build_arp_invalid_sender_mac(arp_values, invalid_mac):
    arp_values["sender_mac"] = invalid_mac

    with pytest.raises(ValueError):
        build_arp(ARP_REQUEST, **arp_values)


@pytest.mark.parametrize(
    "invalid_mac",
    [
        "invalid",
        "00:11:22:33:44",
        "00:11:22:33:44:55:66",
        "00:11:22:33:44:GG",
        "",
    ],
)
def test_build_arp_invalid_target_mac(arp_values, invalid_mac):
    arp_values["target_mac"] = invalid_mac

    with pytest.raises(ValueError):
        build_arp(ARP_REQUEST, **arp_values)


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.168.1.1",
        "192.168.1",
        "192.168.1.256",
        "not_an_ip",
        "",
        "2001:db8::1",
    ],
)
def test_build_arp_invalid_sender_ip(arp_values, invalid_ip):
    arp_values["sender_ip"] = invalid_ip

    with pytest.raises(ipaddress.AddressValueError):
        build_arp(ARP_REQUEST, **arp_values)


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.168.1.1",
        "192.168.1",
        "192.168.1.256",
        "not_an_ip",
        "",
        "2001:db8::1",
    ],
)
def test_build_arp_invalid_target_ip(arp_values, invalid_ip):
    arp_values["target_ip"] = invalid_ip

    with pytest.raises(ipaddress.AddressValueError):
        build_arp(ARP_REQUEST, **arp_values)
