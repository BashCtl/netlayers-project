def format_mac(input_bytes: bytes):
    if len(input_bytes) != 6:
        raise ValueError("A MAC address must be exactly 6 bytes")
    return ":".join(f"{byte:02x}" for byte in input_bytes)


def format_ip(ip_bytes: bytes):
    if len(ip_bytes) != 4:
        raise ValueError("An IP address must be exactly 4 bytes")

    return ".".join(str(byte) for byte in ip_bytes)
