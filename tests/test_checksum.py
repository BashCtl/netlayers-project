import pytest

from netlayers.checksum import internet_checksum


def test_empty_data():
    assert internet_checksum(b"") == 0xFFFF


def test_single_zero_byte():
    assert internet_checksum(b"\x00") == 0xFFFF


def test_single_nonzero_byte():
    # Odd-length data is padded with a zero byte.
    assert internet_checksum(b"\x01") == 0xFEFF


def test_two_zero_bytes():
    assert internet_checksum(b"\x00\x00") == 0xFFFF


def test_two_nonzero_bytes():
    assert internet_checksum(b"\x01\x02") == 0xFEFD


def test_known_checksum():
    data = bytes.fromhex("0001 F203 F4F5 F6F7")
    assert internet_checksum(data) == 0x220D


def test_odd_length_data():
    data = bytes.fromhex("010203")
    # Equivalent to 0x0102 + 0x0300
    assert internet_checksum(data) == 0xFBFD


def test_even_length_data():
    data = bytes.fromhex("01020304")
    # 0x0102 + 0x0304 = 0x0406
    assert internet_checksum(data) == 0xFBF9


def test_overflow_handling():
    data = bytes.fromhex("FFFF 0001")

    assert internet_checksum(data) == 0xFFFE


def test_multiple_overflows():
    data = bytes.fromhex("FFFF FFFF FFFF")

    assert internet_checksum(data) == 0x0000


def test_all_ones():
    data = bytes.fromhex("FFFF")
    assert internet_checksum(data) == 0x0000


def test_all_zeros():
    data = bytes(10)
    assert internet_checksum(data) == 0xFFFF


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"\x00\x01", 0xFFFE),
        (b"\x00\x02", 0xFFFD),
        (b"\xff\xfe", 0x0001),
        (b"\x12\x34", 0xEDCB),
        (b"\xab\xcd", 0x5432),
    ],
)
def test_known_values(data, expected):
    assert internet_checksum(data) == expected


def test_result_is_16_bit_integer():
    data = bytes.fromhex("FFFF FFFF 1234 5678")

    result = internet_checksum(data)

    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFF


def test_input_is_not_modified():
    data = b"\x01\x02\x03"
    original = data

    internet_checksum(data)

    assert data == original
