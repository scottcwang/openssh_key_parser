import secrets

import pytest

from openssh_key.pascal_style_byte_stream import PascalStyleByteStream, PascalStyleFormatInstruction


def test_read_fixed_bytes():
    test_bytes = b'\x01\x02\x03\x04'
    byte_stream = PascalStyleByteStream(test_bytes)
    result = byte_stream.read_fixed_bytes(4)
    assert result == test_bytes


def test_read_fixed_bytes_underfull():
    test_bytes = b'\x01\x02\x03\x04'
    byte_stream = PascalStyleByteStream(test_bytes)
    with pytest.raises(EOFError):
        byte_stream.read_fixed_bytes(5)


def test_read_fixed_bytes_overfull():
    test_bytes = b'\x01\x02\x03\x04'
    byte_stream = PascalStyleByteStream(test_bytes)
    byte_stream.read_fixed_bytes(3)
    assert byte_stream.read() == b'\x04'


def test_read_fixed_bytes_zero():
    test_bytes = b'\x01\x02\x03\x04'
    byte_stream = PascalStyleByteStream(test_bytes)
    byte_stream.read_fixed_bytes(0)
    assert byte_stream.read() == test_bytes


def test_read_pascal_bytes():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x02'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_pascal_bytes(4)
    assert result == b'\x02'


def test_read_negative_pascal_bytes():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x02'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    with pytest.raises(ValueError):
        byte_stream.read_pascal_bytes(-1)


def test_read_pascal_bytes_underfull_length():
    pascal_bytes = b'\x00\x00\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    with pytest.raises(EOFError):
        byte_stream.read_from_format_instruction(
            PascalStyleFormatInstruction.STRING)


def test_read_pascal_bytes_underfull_string():
    pascal_bytes = b'\x00\x00\x00\x04' + b'\x00\x00\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    with pytest.raises(EOFError):
        byte_stream.read_from_format_instruction(
            PascalStyleFormatInstruction.STRING)


def test_read_pascal_bytes_overfull():
    test_string = secrets.token_urlsafe(secrets.randbelow(32))
    test_string_encoded = test_string.encode()
    pascal_bytes = len(test_string_encoded).to_bytes(
        4, byteorder='big') + test_string_encoded
    pascal_bytes = pascal_bytes + b'\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.STRING)
    assert byte_stream.read() == b'\x00'


def test_read_from_struct_format_instruction():
    test_int = secrets.randbits(16)
    test_bytes = test_int.to_bytes(4, byteorder='big')
    byte_stream = PascalStyleByteStream(test_bytes)
    result = byte_stream.read_from_format_instruction('>I')
    assert result == test_int


def test_read_from_string_format_instruction():
    # random ascii string of random length
    test_string = secrets.token_urlsafe(secrets.randbelow(32))
    test_string_encoded = test_string.encode()
    pascal_bytes = len(test_string_encoded).to_bytes(
        4, byteorder='big') + test_string_encoded
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.STRING)
    assert result == test_string


def test_read_from_bytes_format_instruction():
    test_bytes = secrets.token_bytes(secrets.randbelow(32))
    pascal_bytes = len(test_bytes).to_bytes(
        4, byteorder='big') + test_bytes
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.BYTES)
    assert result == test_bytes


def test_read_from_pos_mpint_format_instruction():
    test_int = secrets.randbelow(2 ** 128) + 1  # +1 guarantees positive
    # 7 bits => 1 byte
    # 8 bits => 2 bytes (MSB is 1, so extra prefix needed for zero byte)
    # 9 bits => 2 bytes
    test_int_bytes = test_int.to_bytes(
        test_int.bit_length() // 8 + 1,  # +1 guarantees zero byte prefix if MSB is 1
        byteorder='big'
    )
    pascal_bytes = len(test_int_bytes).to_bytes(
        4, byteorder='big') + test_int_bytes
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.MPINT)
    assert result == test_int


def test_read_from_neg_mpint_format_instruction():
    test_int = -secrets.randbelow(2 ** 12) - 1  # -1 guarantees negative
    # 8 bits => 1 byte
    # 9 bits => 2 bytes
    test_int_bytes = test_int.to_bytes(
        (test_int.bit_length() - 1) // 8 + 1,
        byteorder='big',
        signed=True
    )
    pascal_bytes = len(test_int_bytes).to_bytes(
        4, byteorder='big') + test_int_bytes
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.MPINT)
    assert result == test_int


def test_read_from_zero_mpint_format_instruction():
    test_int = 0
    test_int_bytes = b'\x00\x00\x00\x00'
    pascal_bytes = len(test_int_bytes).to_bytes(
        4, byteorder='big') + test_int_bytes
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.MPINT)
    assert result == test_int


def test_read_from_string_format_instruction_length():
    # random ascii string of random length
    test_string = secrets.token_urlsafe(secrets.randbelow(32))
    test_string_encoded = test_string.encode()
    pascal_bytes = len(test_string_encoded).to_bytes(
        8, byteorder='big') + test_string_encoded
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.STRING,
        string_length_size=8
    )
    assert result == test_string


def test_read_from_pascal_underfull_length():
    pascal_bytes = b'\x00\x00\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    with pytest.raises(EOFError):
        byte_stream.read_from_format_instruction(
            PascalStyleFormatInstruction.STRING)


def test_read_from_pascal_underfull_string():
    pascal_bytes = b'\x00\x00\x00\x04' + b'\x00\x00\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    with pytest.raises(EOFError):
        byte_stream.read_from_format_instruction(
            PascalStyleFormatInstruction.STRING)


def test_read_from_pascal_overfull():
    test_string = secrets.token_urlsafe(secrets.randbelow(32))
    test_string_encoded = test_string.encode()
    pascal_bytes = len(test_string_encoded).to_bytes(
        4, byteorder='big') + test_string_encoded
    pascal_bytes = pascal_bytes + b'\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.STRING)
    assert byte_stream.read() == b'\x00'


def test_read_from_format_instructions_dict():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instructions_dict({
        'first': PascalStyleFormatInstruction.BYTES,
        'second': '>I'
    })
    assert result == {
        'first': b'\x00',
        'second': 2
    }


def test_read_from_empty_format_instructions_dict():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instructions_dict({})
    assert result == {}


def test_read_from_format_instructions_dict_underfull():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    with pytest.raises(EOFError):
        byte_stream.read_from_format_instructions_dict({
            'first': PascalStyleFormatInstruction.BYTES,
            'second': '>I',
        })


def test_read_from_format_instructions_dict_overfull():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02' \
        + b'\x03'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    byte_stream.read_from_format_instructions_dict({
        'first': PascalStyleFormatInstruction.BYTES,
        'second': '>I',
    })
    assert byte_stream.read() == b'\x03'


def test_read_from_format_instructions_dict_length():
    pascal_bytes = b'\x01' + b'\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instructions_dict({
        'first': {
            'format_instruction': PascalStyleFormatInstruction.BYTES,
            'string_length_size': 1
        }
    })
    assert result == {
        'first': b'\x00'
    }
