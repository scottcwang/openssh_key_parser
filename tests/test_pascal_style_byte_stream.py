import secrets

import pytest

from openssh_key.pascal_style_byte_stream import PascalStyleByteStream, PascalStyleFormatInstruction


def test_read_from_struct_format_instruction():
    test_int = secrets.randbits(16)
    test_bytes = test_int.to_bytes(4, byteorder='big')
    byte_stream = PascalStyleByteStream(test_bytes)
    result = byte_stream.read_from_format_instruction('>I')
    assert result == test_int

