import ipaddress
import re
import struct


def format_mac(input_bytes: bytes) -> str:
    if len(input_bytes) != 6:
        raise ValueError("A MAC address must be exactly 6 bytes")
    return ":".join(f"{byte:02x}" for byte in input_bytes)


def format_ip(ip_bytes: bytes) -> str:
    if len(ip_bytes) != 4:
        raise ValueError("An IP address must be exactly 4 bytes")

    return ".".join(str(byte) for byte in ip_bytes)


def hexdump(data: bytes):
    result = []

    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_column = " ".join(f"{c:02x}" for c in chunk)
        ascii_column = "".join(
            chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
        )
        row = f"{i:08x}  {hex_column.ljust(47)}  |{ascii_column}|"

        result.append(row)

    return "\n".join(result)


def parse_mac(mac: str) -> bytes:
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        raise ValueError(f"Invalid MAC address: {mac}")

    return bytes.fromhex(mac.replace(":", ""))


def parse_ip(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed


def build_pseudo_header(src_ip: str, dst_ip: str, protocol: int, length: int) -> bytes:
    """The pseudo-header is used only for checksum calculation and is never sent on the wire."""
    
    if not 0 <= protocol <= 0xFF:
        raise ValueError(f"Protocol out of range: {protocol}")
    if not 0 <= length <= 0xFFFF:
        raise ValueError(f"Length out of range: {length}")

    src_ip_bytes = parse_ip(src_ip)
    dst_ip_bytes = parse_ip(dst_ip)

    return struct.pack(
        "!4s4sHH",
        src_ip_bytes,
        dst_ip_bytes,
        protocol,
        length,
    )
