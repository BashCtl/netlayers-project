import struct

import pytest

from tools import traceroute as traceroute_module


def _embedded_echo_request(identifier=123, sequence=4):
    ip_header = bytearray(20)
    ip_header[0] = 0x45
    ip_header[9] = traceroute_module.IP_PROTO_ICMP
    icmp_header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    return bytes(ip_header) + icmp_header


def test_is_echo_reply_to_probe_matches_reply():
    ip_reply = {"src_ip": "192.0.2.1"}
    icmp = {
        "type": traceroute_module.ICMP_ECHO_REPLY,
        "code": traceroute_module.ICMP_CODE_ECHO,
        "identifier": 123,
        "sequence": 4,
    }

    assert traceroute_module.is_echo_reply_to_probe(
        ip_reply, icmp, 123, 4, "192.0.2.1"
    )


@pytest.mark.parametrize(
    ("field", "value"), [("sequence", 5), ("code", 1)]
)
def test_is_echo_reply_to_probe_rejects_non_matching_reply(field, value):
    ip_reply = {"src_ip": "192.0.2.1"}
    icmp = {
        "type": traceroute_module.ICMP_ECHO_REPLY,
        "code": traceroute_module.ICMP_CODE_ECHO,
        "identifier": 123,
        "sequence": 4,
    }
    icmp[field] = value

    assert not traceroute_module.is_echo_reply_to_probe(
        ip_reply, icmp, 123, 4, "192.0.2.1"
    )


def test_extract_probe_ids_from_embedded_packet():
    assert traceroute_module.extract_probe_ids(_embedded_echo_request()) == (123, 4)


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x45" + b"\x00" * 27, b"\x45" + b"\x00" * 8 + b"\x06" + b"\x00" * 19],
)
def test_extract_probe_ids_rejects_invalid_or_short_payload(payload):
    assert traceroute_module.extract_probe_ids(payload) is None


def test_is_route_reply_to_probe_matches_time_exceeded():
    icmp = {
        "type": traceroute_module.ICMP_TIME_EXCEEDED,
        "code": traceroute_module.ICMP_CODE_TTL_EXCEEDED,
        "payload": _embedded_echo_request(),
    }

    assert traceroute_module.is_route_reply_to_probe(icmp, 123, 4)


def test_traceroute_rejects_max_hops_outside_supported_range():
    with pytest.raises(ValueError, match="max_hops must be between 1 and 255"):
        traceroute_module.traceroute("192.0.2.1", max_hops=0)
