def format_mac(input_bytes: bytes):
    if len(input_bytes) != 6:
        raise ValueError("A MAC address must be exactly 6 bytes")
    return ":".join(f"{byte:02x}" for byte in input_bytes)


print(format_mac(b"\xaa\xbb\xcc\xdd\xee\xff"))
