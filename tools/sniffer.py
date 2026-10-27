import socket
from contextlib import ExitStack
from datetime import UTC, datetime
from itertools import count as forever
from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter

from netlayers.ethernet import parse_frame
from netlayers.utils import hexdump


class TxtWriter:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a", encoding="utf-8")

    def write(self, frame: bytes, captured_at: str) -> None:
        self.file.write(f"{captured_at} -> {frame.hex()}\n")

    def close(self) -> None:
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class PcapFileWriter:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.writer = PcapWriter(str(self.path), append=True, sync=True)

    def write(self, frame: bytes, captured_at: str) -> None:
        pkt = Ether(frame)
        pkt.time = datetime.fromisoformat(captured_at).timestamp()
        self.writer.write(pkt)

    def close(self):
        self.writer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def display_frame(
    raw_data: bytes,
    captured_at: str,
    display: str | None,
):
    if display == "raw":
        print("-" * 80)
        print(hexdump(raw_data))
    elif display == "parsed":
        parsed_ether_frame = parse_frame(raw_data)
        print(f"\nEhernet Frame captured at: {captured_at}")
        print("-" * 15)
        print(f"Destination MAC: {parsed_ether_frame['dst_mac']}")
        print(f"Source MAC: {parsed_ether_frame['src_mac']}")
        print(f"Ethertype: {parsed_ether_frame['ethertype']}")
        print(f"VLAN ID: {parsed_ether_frame['vlan_id']}")
        print(f"Payload: {len(parsed_ether_frame['payload'])} bytes")
    else:
        raise ValueError("Invalid display value")


def sniff(
    interface: str,
    *,
    count: int = 0,
    display: str | None = "parsed",
    txt_file: str | None = None,
    pcap_file: str | None = None,
):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(socket.ETH_P_ALL))
    try:
        s.bind((interface, 0))

        ether_frames = []
        frames = range(count) if count > 0 else forever()

        writers = []
        if txt_file:
            writers.append(TxtWriter(txt_file))
        if pcap_file:
            writers.append(PcapFileWriter(pcap_file))

        with ExitStack() as stack:
            for w in writers:
                stack.enter_context(w)

            for _ in frames:
                raw_data, addr = s.recvfrom(65565)
                captured_at = datetime.now(UTC).isoformat()
                for writer in writers:
                    writer.write(raw_data, captured_at)
                if display is not None:
                    display_frame(raw_data, display=display, captured_at=captured_at)

                ether_frames.append(raw_data)
        return ether_frames
    except KeyboardInterrupt:
        print("\nStopping capture.")
    except OSError as e:
        print(f"Socket error: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    sniff(
        "vethA",
        txt_file="./capture.txt",
        pcap_file="capture.pcap",
        display="parsed",
        count=5,
    )
