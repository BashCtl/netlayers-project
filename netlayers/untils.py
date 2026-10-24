def format_mac(input_bytes: bytes):
    if len(input_bytes) != 6:
        raise ValueError("A MAC address must be exactly 6 bytes")
    return ":".join(f"{byte:02x}" for byte in input_bytes)


def format_ip(ip_bytes: bytes):
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



