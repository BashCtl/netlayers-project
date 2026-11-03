import argparse
import socket
from contextlib import ExitStack
from datetime import UTC, datetime
from itertools import count as forever

from netlayers.dissect import dissect
from netlayers.formatters import FORMATTERS
from netlayers.utils import hexdump
from netlayers.writers import PcapFileWriter, TxtWriter


def display_data(
    raw_data: bytes,
    captured_at: str,
    display: str | None,
):
    if display == "raw":
        print("-" * 80)
        print(f"Captured at: {captured_at}")
        print(hexdump(raw_data))
    elif display == "parsed":
        layers = dissect(raw_data)
        for name, layer in layers.items():
            print("-" * 100)
            print(f"Captured at: {captured_at}")
            print(FORMATTERS[name](layer))
    else:
        raise ValueError("Invalid display value")


def sniff(
    interface: str,
    *,
    count: int = 0,
    display: str | None = "parsed",
    txt_file: str | None = None,
    pcap_file: str | None = None,
) -> None:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(socket.ETH_P_ALL))
    try:
        s.bind((interface, 0))

        frames = range(count) if count > 0 else forever()

        writers = []

        with ExitStack() as stack:
            if txt_file:
                writers.append(TxtWriter(txt_file))
            if pcap_file:
                writers.append(PcapFileWriter(pcap_file))

            for w in writers:
                stack.enter_context(w)

            for _ in frames:
                raw_data, addr = s.recvfrom(65535)
                captured_at = datetime.now(UTC).isoformat()
                for writer in writers:
                    writer.write(raw_data, captured_at)
                if display is not None:
                    try:
                        display_data(
                            raw_data, display=display, captured_at=captured_at
                        )
                    except ValueError as e:
                        print(f"Malformed frame skipped: {e}")

    except KeyboardInterrupt:
        print("\nStopping capture.")
    except OSError as e:
        print(f"Socket error: {e}")
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser(description="Packet sniffer")
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        required=True,
        help="Interface to capture frames from",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture. Default: unlimited",
    )
    parser.add_argument(
        "-d",
        "--display",
        type=str,
        choices=["raw", "parsed"],
        default="parsed",
        help="Display format: raw or parsed",
    )
    parser.add_argument(
        "--text-file",
        type=str,
        help="Path to save packets in hexadecimal format",
    )
    parser.add_argument(
        "--pcap-file",
        type=str,
        help="Path to save captured packets in PCAP format",
    )

    try:
        args = parser.parse_args()
        if args.count < 0:
            parser.error("--count must be 0 or greater")
        display = None if args.display == "none" else args.display

        sniff(
            interface=args.interface,
            count=args.count,
            display=display,
            txt_file=args.text_file,
            pcap_file=args.pcap_file,
        )

    except ValueError as e:
        print(f"Value error: {e}")


if __name__ == "__main__":
    main()
