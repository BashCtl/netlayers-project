from netlayers.ethernet import parse_frame
import pytest


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
