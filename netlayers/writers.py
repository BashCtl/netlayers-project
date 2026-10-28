from datetime import datetime
from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.utils import PcapWriter


class TxtWriter:
    def __init__(self, path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a", encoding="utf-8")

    def write(self, frame: bytes, captured_at: str) -> None:
        self.file.write(f"{captured_at} {frame.hex()}\n")

    def close(self) -> None:
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class PcapFileWriter:
    def __init__(self, path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.writer = PcapWriter(str(self.path), append=True)

    def write(self, frame: bytes, captured_at: str) -> None:
        pkt = Ether(frame)
        pkt.time = datetime.fromisoformat(captured_at).timestamp()
        self.writer.write(pkt)

    def close(self) -> None:
        self.writer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
