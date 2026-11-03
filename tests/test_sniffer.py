from datetime import datetime
from unittest.mock import MagicMock

import pytest

from tools import sniffer


def test_display_data_raw_prints_timestamp_and_hexdump(monkeypatch, capsys):
    monkeypatch.setattr(sniffer, "hexdump", lambda data: "HEX DUMP")

    sniffer.display_data(b"frame", "2026-11-03T12:00:00+00:00", "raw")

    output = capsys.readouterr().out
    assert "Captured at: 2026-11-03T12:00:00+00:00" in output
    assert "HEX DUMP" in output
    assert "-" * 80 in output


def test_display_data_parsed_formats_each_layer(monkeypatch, capsys):
    monkeypatch.setattr(
        sniffer,
        "dissect",
        lambda data: {"ethernet": {"ethertype": 0x0800}, "ipv4": {"ttl": 64}},
    )
    monkeypatch.setattr(
        sniffer,
        "FORMATTERS",
        {"ethernet": lambda layer: "ETHERNET", "ipv4": lambda layer: "IPV4"},
    )

    sniffer.display_data(b"frame", "captured", "parsed")

    output = capsys.readouterr().out
    assert output.count("Captured at: captured") == 2
    assert "ETHERNET" in output
    assert "IPV4" in output
    assert output.count("-" * 100) == 2


def test_display_data_rejects_invalid_display_mode():
    with pytest.raises(ValueError, match="Invalid display value"):
        sniffer.display_data(b"frame", "captured", "other")


def test_sniff_captures_count_writes_frames_and_closes_socket(monkeypatch, capsys):
    packet_socket = MagicMock()
    packet_socket.recvfrom.side_effect = [
        (b"first", ("eth0", 0)),
        (b"second", ("eth0", 0)),
    ]
    monkeypatch.setattr(sniffer.socket, "socket", lambda *args: packet_socket)
    monkeypatch.setattr(sniffer.socket, "ntohs", lambda value: value)
    text_writer = MagicMock()
    text_writer.__enter__.return_value = text_writer
    pcap_writer = MagicMock()
    pcap_writer.__enter__.return_value = pcap_writer
    monkeypatch.setattr(sniffer, "TxtWriter", lambda path: text_writer)
    monkeypatch.setattr(sniffer, "PcapFileWriter", lambda path: pcap_writer)
    displayed = []
    monkeypatch.setattr(
        sniffer,
        "display_data",
        lambda raw_data, captured_at, display: displayed.append(
            (raw_data, captured_at, display)
        ),
    )

    sniffer.sniff(
        "eth0", count=2, display="raw", txt_file="capture.txt", pcap_file="capture.pcap"
    )

    packet_socket.bind.assert_called_once_with(("eth0", 0))
    packet_socket.close.assert_called_once_with()
    text_writer.__enter__.assert_called_once()
    text_writer.__exit__.assert_called_once()
    pcap_writer.__enter__.assert_called_once()
    pcap_writer.__exit__.assert_called_once()
    assert [call.args[0] for call in text_writer.write.call_args_list] == [
        b"first",
        b"second",
    ]
    assert [call.args[0] for call in pcap_writer.write.call_args_list] == [
        b"first",
        b"second",
    ]
    assert [data for data, _, _ in displayed] == [b"first", b"second"]
    assert all(display == "raw" for _, _, display in displayed)
    assert all(
        datetime.fromisoformat(timestamp).utcoffset().total_seconds() == 0
        for _, timestamp, _ in displayed
    )
    assert capsys.readouterr().out == ""


def test_sniff_skips_display_when_disabled(monkeypatch):
    packet_socket = MagicMock()
    packet_socket.recvfrom.return_value = (b"frame", ("eth0", 0))
    monkeypatch.setattr(sniffer.socket, "socket", lambda *args: packet_socket)
    monkeypatch.setattr(sniffer.socket, "ntohs", lambda value: value)
    monkeypatch.setattr(
        sniffer,
        "display_data",
        lambda *args, **kwargs: pytest.fail("display_data should not be called"),
    )

    sniffer.sniff("eth0", count=1, display=None)

    packet_socket.close.assert_called_once_with()


def test_sniff_reports_socket_error_and_closes_socket(monkeypatch, capsys):
    packet_socket = MagicMock()
    packet_socket.bind.side_effect = OSError("permission denied")
    monkeypatch.setattr(sniffer.socket, "socket", lambda *args: packet_socket)
    monkeypatch.setattr(sniffer.socket, "ntohs", lambda value: value)

    sniffer.sniff("eth0", count=1)

    assert "Socket error: permission denied" in capsys.readouterr().out
    packet_socket.close.assert_called_once_with()


def test_main_passes_cli_options_to_sniff(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "sys.argv",
        [
            "sniffer",
            "--interface",
            "eth0",
            "--count",
            "2",
            "--display",
            "raw",
            "--text-file",
            "capture.txt",
            "--pcap-file",
            "capture.pcap",
        ],
    )
    monkeypatch.setattr(sniffer, "sniff", lambda **kwargs: calls.append(kwargs))

    sniffer.main()

    assert calls == [
        {
            "interface": "eth0",
            "count": 2,
            "display": "raw",
            "txt_file": "capture.txt",
            "pcap_file": "capture.pcap",
        }
    ]


def test_main_rejects_negative_count(monkeypatch):
    monkeypatch.setattr("sys.argv", ["sniffer", "--interface", "eth0", "-c", "-1"])

    with pytest.raises(SystemExit):
        sniffer.main()
