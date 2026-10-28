from datetime import datetime
from pathlib import Path

import pytest
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader

from netlayers.writers import PcapFileWriter, TxtWriter


@pytest.fixture
def ethernet_frame():
    return bytes(
        Ether(
            dst="ff:ff:ff:ff:ff:ff",
            src="00:11:22:33:44:55",
            type=0x0800,
        )
        / b"\x45\x00\x00\x14"
        + Ether()[:0]  # type: ignore
    )


class TestTxtWriter:
    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "frames.txt"
        writer = TxtWriter(path)
        writer.close()

        assert path.exists()
        assert path.parent.is_dir()

    def test_write_frame(self, tmp_path):
        path = tmp_path / "frames.txt"
        frame = b"\x01\x02\xab\xcd"
        captured_at = "2026-10-28T10:30:00"

        with TxtWriter(path) as writer:
            writer.write(frame, captured_at)

        assert path.read_text(encoding="utf-8") == ("2026-10-28T10:30:00 0102abcd\n")

    def test_write_multiple_frames(self, tmp_path):
        path = tmp_path / "frames.txt"

        with TxtWriter(path) as writer:
            writer.write(b"\x01\x02", "2026-10-28T10:30:00")
            writer.write(b"\xaa\xbb", "2026-10-28T10:30:01")

        assert path.read_text(encoding="utf-8").splitlines() == [
            "2026-10-28T10:30:00 0102",
            "2026-10-28T10:30:01 aabb",
        ]

    def test_appends_to_existing_file(self, tmp_path):
        path = tmp_path / "frames.txt"
        path.write_text("existing data\n", encoding="utf-8")

        with TxtWriter(path) as writer:
            writer.write(b"\x12\x34", "2026-10-28T10:30:00")

        assert path.read_text(encoding="utf-8") == (
            "existing data\n2026-10-28T10:30:00 1234\n"
        )


class TestPcapFileWriter:
    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "frames.pcap"
        writer = PcapFileWriter(path)
        writer.close()

        assert path.exists()
        assert path.parent.is_dir()

    def test_write_frame(self, tmp_path):
        path = tmp_path / "frames.pcap"
        frame = bytes(
            Ether(
                dst="ff:ff:ff:ff:ff:ff",
                src="00:11:22:33:44:55",
                type=0x0800,
            )
        )
        captured_at = "2026-10-28T10:30:00"

        with PcapFileWriter(path) as writer:
            writer.write(frame, captured_at)

        with PcapReader(str(path)) as reader:
            packets = list(reader)

        assert len(packets) == 1
        assert bytes(packets[0]) == frame
        assert packets[0].time == datetime.fromisoformat(captured_at).timestamp()

    def test_write_multiple_frames(self, tmp_path):
        path = tmp_path / "frames.pcap"
        frames = [
            bytes(Ether() / b"\x01\x02"),
            bytes(Ether() / b"\xaa\xbb"),
        ]

        with PcapFileWriter(path) as writer:
            writer.write(frames[0], "2026-10-28T10:30:00")
            writer.write(frames[1], "2026-10-28T10:30:01")

        with PcapReader(str(path)) as reader:
            packets = list(reader)

        assert len(packets) == 2
        assert [bytes(packet) for packet in packets] == frames

    def test_appends_to_existing_pcap(self, tmp_path):
        path = tmp_path / "frames.pcap"
        first_frame = bytes(Ether() / b"\x01\x02")
        second_frame = bytes(Ether() / b"\xaa\xbb")

        with PcapFileWriter(path) as writer:
            writer.write(first_frame, "2026-10-28T10:30:00")

        with PcapFileWriter(path) as writer:
            writer.write(second_frame, "2026-10-28T10:30:01")

        with PcapReader(str(path)) as reader:
            packets = list(reader)

        assert len(packets) == 2
        assert bytes(packets[0]) == first_frame
        assert bytes(packets[1]) == second_frame
