import pytest

from netlayers.arp import parse_arp

# Valid ARP Ethernet frame 
ETHER_FRAME = bytes.fromhex(
    "ffffffffffff9660f528217508060001080006040001"
    "9660f52821750a0000010000000000000a000002"
)

# ARP payload starts after the 14-byte Ethernet header
ARP_PAYLOAD = ETHER_FRAME[14:]


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
