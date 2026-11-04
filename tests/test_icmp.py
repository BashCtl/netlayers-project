import struct

import pytest

from netlayers.checksum import internet_checksum
from netlayers.constant import (
    ICMP_CODE_ECHO,
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    ICMP_HEADER_LEN,
)
from netlayers.icmp import build_icmp_echo_request, parse_icmp


@pytest.fixture
def ethernet_frame():
    return bytes.fromhex(
        "1a46f73375a89660f528217508004500005476df40004001afc7"
        "0a0000010a0000020800f75a49c00001f856e86a00000000114f"
        "060000000000101112131415161718191a1b1c1d1e1f20212223"
        "2425262728292a2b2c2d2e2f3031323334353637"
    )


@pytest.fixture
def ipv4_payload(ethernet_frame):
    ethernet_header_len = 14
    ipv4_header_len = (ethernet_frame[ethernet_header_len] & 0x0F) * 4

    return ethernet_frame[ethernet_header_len + ipv4_header_len :]


def test_parse_icmp_echo_request(ipv4_payload):
    result = parse_icmp(ipv4_payload)

    assert result["type"] == ICMP_ECHO_REQUEST
    assert result["code"] == 0
    assert result["checksum"] == 0xF75A
    assert result["identifier"] == 0x49C0
    assert result["sequence"] == 1
    assert result["rest_of_header"] == bytes.fromhex("49c00001")
    assert result["payload"] == bytes.fromhex(
        "f856e86a00000000114f060000000000"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "3031323334353637"
    )


def test_parse_icmp_echo_reply():
    identifier = 0x1234
    sequence = 5
    payload = b"test payload"

    packet = (
        struct.pack(
            "!BBHHH",
            ICMP_ECHO_REPLY,
            0,
            0xABCD,
            identifier,
            sequence,
        )
        + payload
    )

    result = parse_icmp(packet)

    assert result["type"] == ICMP_ECHO_REPLY
    assert result["code"] == 0
    assert result["checksum"] == 0xABCD
    assert result["identifier"] == identifier
    assert result["sequence"] == sequence
    assert result["rest_of_header"] == struct.pack("!HH", identifier, sequence)
    assert result["payload"] == payload


def test_parse_icmp_other_type():
    icmp_type = 3
    code = 1
    checksum = 0x1234
    rest_of_header = bytes.fromhex("00000000")
    payload = b"additional data"

    packet = struct.pack("!BBH", icmp_type, code, checksum) + rest_of_header + payload

    result = parse_icmp(packet)

    assert result["type"] == icmp_type
    assert result["code"] == code
    assert result["checksum"] == checksum
    assert result["rest_of_header"] == rest_of_header
    assert result["payload"] == payload

    assert "identifier" not in result
    assert "sequence" not in result


def test_parse_icmp_without_payload():
    packet = struct.pack(
        "!BBHHH",
        ICMP_ECHO_REQUEST,
        0,
        0x1234,
        100,
        1,
    )

    result = parse_icmp(packet)

    assert result["payload"] == b""
    assert result["identifier"] == 100
    assert result["sequence"] == 1


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"\x08",
        b"\x08\x00",
        b"\x08\x00\x00\x00",
        b"\x08\x00\x00\x00\x00\x00\x00",
    ],
)
def test_parse_icmp_invalid_packet(packet):
    with pytest.raises(ValueError, match="Invalid ICMP packet"):
        parse_icmp(packet)


def test_parse_icmp_exact_header_length():
    packet = struct.pack(
        "!BBHHH",
        ICMP_ECHO_REQUEST,
        0,
        0x1234,
        0x5678,
        1,
    )

    assert len(packet) == ICMP_HEADER_LEN

    result = parse_icmp(packet)

    assert result["payload"] == b""
    assert result["identifier"] == 0x5678
    assert result["sequence"] == 1


def test_build_icmp_echo_request_empty_payload():
    packet = build_icmp_echo_request(
        identifier=1,
        sequence=1,
    )

    assert isinstance(packet, bytes)
    assert len(packet) == 8


def test_build_icmp_echo_request_with_payload():
    payload = b"Hello, ICMP!"

    packet = build_icmp_echo_request(
        identifier=1,
        sequence=1,
        payload=payload,
    )

    assert len(packet) == 8 + len(payload)
    assert packet[8:] == payload


def test_icmp_packet_header():
    packet = build_icmp_echo_request(
        identifier=1234,
        sequence=5,
    )

    icmp_type, code, checksum, identifier, sequence = struct.unpack(
        "!BBHHH", packet[:8]
    )

    assert icmp_type == ICMP_ECHO_REQUEST
    assert code == ICMP_CODE_ECHO
    assert identifier == 1234
    assert sequence == 5
    assert isinstance(checksum, int)


def test_icmp_checksum_is_valid():
    payload = b"Hello, ICMP!"

    packet = build_icmp_echo_request(
        identifier=1234,
        sequence=5,
        payload=payload,
    )

    assert internet_checksum(packet) == 0


def test_icmp_checksum_changes_with_payload():
    packet1 = build_icmp_echo_request(
        identifier=1,
        sequence=1,
        payload=b"Hello",
    )

    packet2 = build_icmp_echo_request(
        identifier=1,
        sequence=1,
        payload=b"World",
    )

    assert packet1[2:4] != packet2[2:4]


def test_icmp_checksum_changes_with_identifier():
    packet1 = build_icmp_echo_request(
        identifier=1,
        sequence=1,
    )

    packet2 = build_icmp_echo_request(
        identifier=2,
        sequence=1,
    )

    assert packet1[2:4] != packet2[2:4]


def test_icmp_checksum_changes_with_sequence():
    packet1 = build_icmp_echo_request(
        identifier=1,
        sequence=1,
    )

    packet2 = build_icmp_echo_request(
        identifier=1,
        sequence=2,
    )

    assert packet1[2:4] != packet2[2:4]


@pytest.mark.parametrize(
    "identifier",
    [-1, 0x10000, 100000],
)
def test_invalid_identifier(identifier):
    with pytest.raises(
        ValueError,
        match="Identifier out of range",
    ):
        build_icmp_echo_request(
            identifier=identifier,
            sequence=1,
        )


@pytest.mark.parametrize(
    "sequence",
    [-1, 0x10000, 100000],
)
def test_invalid_sequence(sequence):
    with pytest.raises(
        ValueError,
        match="Sequence out of range",
    ):
        build_icmp_echo_request(
            identifier=1,
            sequence=sequence,
        )


@pytest.mark.parametrize(
    "identifier",
    [0, 1, 0xFFFF],
)
def test_valid_identifier_boundaries(identifier):
    packet = build_icmp_echo_request(
        identifier=identifier,
        sequence=1,
    )

    unpacked = struct.unpack("!BBHHH", packet[:8])

    assert unpacked[3] == identifier


@pytest.mark.parametrize(
    "sequence",
    [0, 1, 0xFFFF],
)
def test_valid_sequence_boundaries(sequence):
    packet = build_icmp_echo_request(
        identifier=1,
        sequence=sequence,
    )

    unpacked = struct.unpack("!BBHHH", packet[:8])

    assert unpacked[4] == sequence


def test_large_payload():
    payload = b"A" * 1400

    packet = build_icmp_echo_request(
        identifier=100,
        sequence=10,
        payload=payload,
    )

    assert len(packet) == 8 + 1400
    assert packet[8:] == payload
    assert internet_checksum(packet) == 0


def test_zero_identifier_and_sequence():
    packet = build_icmp_echo_request(
        identifier=0,
        sequence=0,
    )

    unpacked = struct.unpack("!BBHHH", packet[:8])

    assert unpacked[3] == 0
    assert unpacked[4] == 0


def test_input_payload_is_not_modified():
    payload = b"\x01\x02\x03\x04"
    original_payload = payload

    build_icmp_echo_request(
        identifier=1,
        sequence=1,
        payload=payload,
    )

    assert payload == original_payload
