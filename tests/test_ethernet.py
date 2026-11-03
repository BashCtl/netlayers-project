import struct

import pytest

from netlayers.constant import ETHER_MAX_PAYLOAD, ETHER_MIN_PAYLOAD
from netlayers.ethernet import build_frame, parse_frame


# Tests parse Ethernet frame
def test_parse_normal_ipv4_ethernet_frame():
    frame = (
        b"\x66\x47\x51\x6b\x63\xcc"
        b"\x00\x11\x22\x33\x44\x55"
        b"\x08\x00"
        b"\x45\x00\x00\x1c\x12\x34\x40\x00\x40\x01\x3c\x6c"
        b"\xc0\xa8\x01\x0a\xc0\xa8\x01\x01"
        b"\x08\x00\xf7\xff\x00\x01\x00\x01"
    )

    result = parse_frame(frame)
    assert result["dst_mac"] == "66:47:51:6b:63:cc"
    assert result["src_mac"] == "00:11:22:33:44:55"
    assert result["ethertype"] == 2048
    assert result["vlan_id"] == None
    assert result["vlan_tci"] == None


def test_parse_vlan_tagged_ipv4_frame_with_vlan_id_1000():
    frame = (
        b"\x66\x47\x51\x6b\x63\xcc"
        b"\x00\x11\x22\x33\x44\x55"
        b"\x81\x00"
        b"\x03\xe8"
        b"\x08\x00"
        b"\x45\x00\x00\x1c\x12\x34\x40\x00\x40\x01\x3c\x6c"
        b"\xc0\xa8\x01\x0a\xc0\xa8\x01\x01"  # IPv4 header
        b"\x08\x00\xf7\xff\x00\x01\x00\x01"  # ICMP Echo Request
    )

    result = parse_frame(frame)
    assert result["dst_mac"] == "66:47:51:6b:63:cc"
    assert result["src_mac"] == "00:11:22:33:44:55"
    assert result["ethertype"] == 2048
    assert result["vlan_id"] == 1000
    assert result["vlan_tci"] == 1000


def test_frame_shorter_than_ethernet_header_raises_error():
    frame = b"\x66\x47\x51\x6b\x63\xcc\x00\x11"
    with pytest.raises(ValueError, match="Invalid Ethernet frame length"):
        parse_frame(frame)


def test_vlan_frame_truncated_before_full_vlan_header():
    frame = (
        b"\x66\x47\x51\x6b\x63\xcc"  # Destination MAC (6 bytes)
        b"\x00\x11\x22\x33\x44\x55"  # Source MAC (6 bytes)
        b"\x81\x00"  # VLAN TPID (2 bytes)
        b"\x03"  # Truncated VLAN TCI (only 1 of 2 bytes)
    )
    with pytest.raises(ValueError, match="Truncated VLAN frame"):
        parse_frame(frame)


# Tests build Ethernate frame
DST_MAC = "AA:BB:CC:DD:EE:FF"
SRC_MAC = "11:22:33:44:55:66"
ETHERTYPE = 0x0800
PAYLOAD = b"Hello, Ethernet!"


def test_build_valid_frame():
    result = build_frame(
        DST_MAC,
        SRC_MAC,
        ETHERTYPE,
        PAYLOAD,
    )

    expected_header = struct.pack(
        "!6s6sH",
        bytes.fromhex("AABBCCDDEEFF"),
        bytes.fromhex("112233445566"),
        ETHERTYPE,
    )

    assert result == expected_header + PAYLOAD


def test_build_frame_with_empty_payload():
    result = build_frame(
        DST_MAC,
        SRC_MAC,
        ETHERTYPE,
    )

    assert len(result) == 14


def test_build_frame_with_default_padding_disabled():
    payload = b"short"

    result = build_frame(
        DST_MAC,
        SRC_MAC,
        ETHERTYPE,
        payload,
    )

    assert result[14:] == payload
    assert len(result) == 14 + len(payload)


def test_build_frame_with_padding():
    payload = b"short"

    result = build_frame(
        DST_MAC,
        SRC_MAC,
        ETHERTYPE,
        payload,
        pad=True,
    )

    assert result[14 : 14 + len(payload)] == payload
    assert len(result[14:]) == ETHER_MIN_PAYLOAD
    assert result[14:] == payload.ljust(ETHER_MIN_PAYLOAD, b"\x00")


def test_padding_not_applied_when_payload_is_large_enough():
    payload = b"A" * ETHER_MIN_PAYLOAD

    result = build_frame(
        DST_MAC,
        SRC_MAC,
        ETHERTYPE,
        payload,
        pad=True,
    )

    assert result[14:] == payload
    assert len(result) == 14 + ETHER_MIN_PAYLOAD


def test_padding_not_applied_when_payload_exceeds_minimum():
    payload = b"A" * (ETHER_MIN_PAYLOAD + 10)

    result = build_frame(
        DST_MAC,
        SRC_MAC,
        ETHERTYPE,
        payload,
        pad=True,
    )

    assert result[14:] == payload


@pytest.mark.parametrize(
    "ethertype",
    [-1, 0x10000, 0x10001],
)
def test_invalid_ethertype(ethertype):
    with pytest.raises(ValueError, match="EtherType out of range"):
        build_frame(
            DST_MAC,
            SRC_MAC,
            ethertype,
            PAYLOAD,
        )


@pytest.mark.parametrize(
    "ethertype",
    [0, 0x0800, 0x0806, 0xFFFF],
)
def test_valid_ethertype_boundaries(ethertype):
    result = build_frame(
        DST_MAC,
        SRC_MAC,
        ethertype,
        PAYLOAD,
    )

    assert struct.unpack("!H", result[12:14])[0] == ethertype


def test_payload_exceeds_mtu():
    payload = b"A" * (ETHER_MAX_PAYLOAD + 1)

    with pytest.raises(ValueError, match="Payload exceeds Ethernet MTU"):
        build_frame(
            DST_MAC,
            SRC_MAC,
            ETHERTYPE,
            payload,
        )


def test_payload_at_mtu_limit():
    payload = b"A" * ETHER_MAX_PAYLOAD

    result = build_frame(
        DST_MAC,
        SRC_MAC,
        ETHERTYPE,
        payload,
    )

    assert len(result) == 14 + ETHER_MAX_PAYLOAD
    assert result[14:] == payload


def test_invalid_destination_mac():
    with pytest.raises(ValueError):
        build_frame(
            "invalid-mac",
            SRC_MAC,
            ETHERTYPE,
            PAYLOAD,
        )


def test_invalid_source_mac():
    with pytest.raises(ValueError):
        build_frame(
            DST_MAC,
            "invalid-mac",
            ETHERTYPE,
            PAYLOAD,
        )
