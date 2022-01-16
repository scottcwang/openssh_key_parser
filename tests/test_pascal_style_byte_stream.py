import pytest
from openssh_key.pascal_style_byte_stream import (
    PascalStyleByteStream, PascalStyleFormatInstruction,
    PascalStyleFormatInstructionStringLengthSize)


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
    with pytest.raises(
        ValueError,
        match='string_length_size must be positive'
    ):
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
    pascal_bytes = b'\x00\x00\x00\x04' + b'abcd' + b'\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.STRING)
    assert byte_stream.read() == b'\x00'


def test_read_from_struct_single_format_instruction():
    test_bytes = b'\x00\x00\x00\x01'
    byte_stream = PascalStyleByteStream(test_bytes)
    result = byte_stream.read_from_format_instruction('>I')
    assert result == 1


def test_read_from_struct_multiple_format_instruction():
    test_bytes = b'\x00\x00\x00\x01\x00\x00\x00\x02'
    byte_stream = PascalStyleByteStream(test_bytes)
    result = byte_stream.read_from_format_instruction('>II')
    assert result == (1, 2)


def test_read_from_string_format_instruction():
    pascal_bytes = b'\x00\x00\x00\x04' + b'abcd'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.STRING)
    assert result == 'abcd'


def test_read_from_bytes_format_instruction():
    pascal_bytes = b'\x00\x00\x00\x04' + b'\x01\x02\x03\x04'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.BYTES)
    assert result == b'\x01\x02\x03\x04'


def test_read_from_pos_mpint_format_instruction():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x7f'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.MPINT)
    assert result == 0x7f


def test_read_from_neg_mpint_format_instruction():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x80'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.MPINT)
    assert result == -0x80


def test_read_from_zero_mpint_format_instruction():
    pascal_bytes = b'\x00\x00\x00\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.MPINT)
    assert result == 0


def test_read_from_string_format_instruction_length():
    pascal_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x04' + b'abcd'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.STRING,
        string_length_size=8
    )
    assert result == 'abcd'


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
    pascal_bytes = b'\x00\x00\x00\x04' + b'abcd' + b'\x00'
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
        'first': PascalStyleFormatInstructionStringLengthSize(
            PascalStyleFormatInstruction.BYTES,
            1
        )
    })
    assert result == {
        'first': b'\x00'
    }


def test_read_repeatedly_from_format_instructions_dict():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02' \
        + b'\x00\x00\x00\x01' + b'\x03' \
        + b'\x00\x00\x00\x04'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_repeatedly_from_format_instructions_dict({
        'first': PascalStyleFormatInstruction.BYTES,
        'second': '>I'
    })
    assert result == [
        {
            'first': b'\x00',
            'second': 2
        },
        {
            'first': b'\x03',
            'second': 4
        }
    ]


def test_read_repeatedly_from_format_instructions_dict_empty_stream():
    byte_stream = PascalStyleByteStream()
    result = byte_stream.read_repeatedly_from_format_instructions_dict({
        'first': PascalStyleFormatInstruction.BYTES,
        'second': '>I'
    })
    assert result == []


def test_read_repeatedly_from_empty_format_instructions_dict():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    with pytest.raises(
        ValueError,
        match='format_instructions_dict cannot be empty'
    ):
        byte_stream.read_repeatedly_from_format_instructions_dict({})


def test_read_repeatedly_from_format_instructions_dict_underfull():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02' \
        + b'\x00\x00\x00\x01' + b'\x03' \
        + b'\x00\x00\x00'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    with pytest.raises(EOFError):
        byte_stream.read_repeatedly_from_format_instructions_dict({
            'first': PascalStyleFormatInstruction.BYTES,
            'second': '>I',
        })


def test_read_repeatedly_from_format_instructions_dict_overfull():
    pascal_bytes = b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02' \
        + b'\x03'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    byte_stream.read_from_format_instructions_dict({
        'first': PascalStyleFormatInstruction.BYTES,
        'second': '>I',
    })
    with pytest.raises(EOFError):
        byte_stream.read_repeatedly_from_format_instructions_dict({
            'first': PascalStyleFormatInstruction.BYTES,
            'second': '>I',
        })


def test_read_repeatedly_from_format_instructions_dict_length():
    pascal_bytes = b'\x01' + b'\x00' + b'\x02' + b'\x01\x02'
    byte_stream = PascalStyleByteStream(pascal_bytes)
    result = byte_stream.read_repeatedly_from_format_instructions_dict({
        'first': PascalStyleFormatInstructionStringLengthSize(
            PascalStyleFormatInstruction.BYTES,
            1
        )
    })
    assert result == [
        {
            'first': b'\x00'
        },
        {
            'first': b'\x01\x02'
        }
    ]


def test_write_from_struct_format_instruction():
    test_int = 1
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instruction('>I', test_int)
    assert byte_stream.getvalue() == b'\x00\x00\x00\x01'


def test_write_from_bytes_format_instruction():
    test_bytes = b'\x00'
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.BYTES,
        test_bytes
    )
    assert byte_stream.getvalue() == b'\x00\x00\x00\x01' + b'\x00'


def test_write_from_string_format_instruction():
    test_string = 'abcd'
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.STRING,
        test_string
    )
    assert byte_stream.getvalue() == b'\x00\x00\x00\x04' + b'abcd'


def test_write_from_string_format_instruction_string_length_size():
    test_string = 'abcd'
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.STRING,
        test_string,
        8
    )
    assert byte_stream.getvalue() == \
        b'\x00\x00\x00\x00\x00\x00\x00\x04' + b'abcd'


def test_write_from_pos_no_prefix_mpint_format_instruction():
    test_int = 0x1000
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.MPINT,
        test_int
    )
    assert byte_stream.getvalue() == b'\x00\x00\x00\x02' + b'\x10\x00'


def test_write_from_pos_with_prefix_mpint_format_instruction():
    test_int = 0x8000
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.MPINT,
        test_int
    )
    assert byte_stream.getvalue() == b'\x00\x00\x00\x03' + b'\x00\x80\x00'


def test_write_from_neg_mpint_format_instruction():
    test_int = -0x8000
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.MPINT,
        test_int
    )
    assert byte_stream.getvalue() == b'\x00\x00\x00\x02' + b'\x80\x00'


def test_write_from_zero_mpint_format_instruction():
    test_int = 0
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.MPINT,
        test_int
    )
    assert byte_stream.getvalue() == b'\x00\x00\x00\x00'


def test_write_from_bytes_format_instruction_bad_class_str():
    test = 'random'
    byte_stream = PascalStyleByteStream()
    with pytest.raises(
        ValueError,
        match='value must be a bytes instance for bytes format instruction'
    ):
        byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            test
        )


def test_write_from_bytes_format_instruction_bad_class_int():
    test = 1
    byte_stream = PascalStyleByteStream()
    with pytest.raises(
        ValueError,
        match='value must be a bytes instance for bytes format instruction'
    ):
        byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            test
        )


def test_write_from_str_format_instruction_bad_class_bytes():
    test = b'random'
    byte_stream = PascalStyleByteStream()
    with pytest.raises(
        ValueError,
        match='value must be a str instance for string format instruction'
    ):
        byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.STRING,
            test
        )


def test_write_from_str_format_instruction_bad_class_int():
    test = 1
    byte_stream = PascalStyleByteStream()
    with pytest.raises(
        ValueError,
        match='value must be a str instance for string format instruction'
    ):
        byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.STRING,
            test
        )


def test_write_from_mpint_format_instruction_bad_class_bytes():
    test = b'random'
    byte_stream = PascalStyleByteStream()
    with pytest.raises(
        ValueError,
        match='value must be an int instance for mpint format instruction'
    ):
        byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.MPINT,
            test
        )


def test_write_from_mpint_format_instruction_bad_class_str():
    test = 'random'
    byte_stream = PascalStyleByteStream()
    with pytest.raises(
        ValueError,
        match='value must be an int instance for mpint format instruction'
    ):
        byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.MPINT,
            test
        )


def test_write_from_format_instructions_dict():
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instructions_dict({
        'first': PascalStyleFormatInstruction.BYTES,
        'second': '>I',
    }, {
        'first': b'\x00',
        'second': 2,
    })
    assert byte_stream.getvalue() == b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02'


def test_write_from_empty_format_instructions_dict():
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instructions_dict({}, {
        'first': b'\x00',
        'second': 2,
    })
    assert byte_stream.getvalue() == b''


def test_write_from_format_instructions_dict_missing_key():
    byte_stream = PascalStyleByteStream()
    with pytest.raises(KeyError):
        byte_stream.write_from_format_instructions_dict({
            'missing': '>I'
        }, {
            'first': b'\x00',
            'second': 2,
        })


def test_write_from_format_instructions_dict_length():
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instructions_dict({
        'first': PascalStyleFormatInstructionStringLengthSize(
            PascalStyleFormatInstruction.BYTES,
            2
        )
    }, {
        'first': b'\x00'
    })
    assert byte_stream.getvalue() == b'\x00\x01' + b'\x00'


def test_write_repeatedly_from_format_instructions_dict():
    byte_stream = PascalStyleByteStream()
    byte_stream.write_repeatedly_from_format_instructions_dict(
        {
            'first': PascalStyleFormatInstruction.BYTES,
            'second': '>I',
        },
        [
            {
                'first': b'\x00',
                'second': 2,
            },
            {
                'first': b'\x01\x02',
                'second': 3
            }
        ]
    )
    assert byte_stream.getvalue() == b'\x00\x00\x00\x01' + b'\x00' \
        + b'\x00\x00\x00\x02' \
        + b'\x00\x00\x00\x02' + b'\x01\x02' \
        + b'\x00\x00\x00\x03'


def test_write_repeatedly_from_format_instructions_dict_empty_list():
    byte_stream = PascalStyleByteStream()
    byte_stream.write_repeatedly_from_format_instructions_dict(
        {
            'first': PascalStyleFormatInstruction.BYTES,
            'second': '>I',
        },
        []
    )
    assert byte_stream.getvalue() == b''


def test_write_repeatedly_from_empty_format_instructions_dict():
    byte_stream = PascalStyleByteStream()
    byte_stream.write_repeatedly_from_format_instructions_dict(
        {},
        [
            {
                'first': b'\x00',
                'second': 2,
            },
            {
                'first': b'\x03',
                'second': 4
            }
        ]
    )
    assert byte_stream.getvalue() == b''


def test_write_repeatedly_from_format_instructions_dict_missing_key():
    byte_stream = PascalStyleByteStream()
    with pytest.raises(KeyError):
        byte_stream.write_repeatedly_from_format_instructions_dict(
            {
                'missing': '>I'
            },
            [
                {
                    'first': b'\x00',
                    'second': 2,
                },
                {

                    'first': b'\x03',
                    'second': 4,
                }
            ]
        )


def test_write_repeatedly_from_format_instructions_dict_length():
    byte_stream = PascalStyleByteStream()
    byte_stream.write_repeatedly_from_format_instructions_dict(
        {
            'first': PascalStyleFormatInstructionStringLengthSize(
                PascalStyleFormatInstruction.BYTES,
                2
            )
        },
        [
            {
                'first': b'\x00'
            },
            {
                'first': b'\x01\x02'
            }
        ]
    )
    assert byte_stream.getvalue() == b'\x00\x01' + b'\x00' \
        + b'\x00\x02' + b'\x01\x02'


def test_check_dict_str():
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 'string'
            },
            {
                'a': PascalStyleFormatInstruction.STRING
            }
        )
    assert not warnings_list


def test_check_dict_bytes():
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': b'\x00'
            },
            {
                'a': PascalStyleFormatInstruction.BYTES
            }
        )
    assert not warnings_list


def test_check_dict_mpint():
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 1
            },
            {
                'a': PascalStyleFormatInstruction.MPINT
            }
        )
    assert not warnings_list


def test_check_dict_incorrect_type():
    with pytest.warns(UserWarning, match='a should be of class int'):
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 'string'
            },
            {
                'a': PascalStyleFormatInstruction.MPINT
            }
        )


def test_check_dict_format_string():
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 1
            },
            {
                'a': '>i'
            }
        )
    assert not warnings_list


def test_check_dict_format_string_too_large():
    with pytest.warns(UserWarning, match='a should be formatted as >i'):
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 2 ** 33
            },
            {
                'a': '>i'
            }
        )


def test_check_dict_two_attributes():
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 1,
                'b': 2
            },
            {
                'a': PascalStyleFormatInstruction.MPINT,
                'b': PascalStyleFormatInstruction.MPINT
            }
        )
    assert not warnings_list


def test_check_dict_missing_attribute():
    with pytest.warns(UserWarning, match='b missing'):
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 1
            },
            {
                'a': PascalStyleFormatInstruction.MPINT,
                'b': PascalStyleFormatInstruction.MPINT
            }
        )


def test_check_dict_extra_attribute():
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 1,
                'b': 2,
                'c': 3
            },
            {
                'a': PascalStyleFormatInstruction.MPINT,
                'b': PascalStyleFormatInstruction.MPINT
            }
        )
    assert not warnings_list


def test_check_dict_length():
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 'string'
            },
            {
                'a': PascalStyleFormatInstructionStringLengthSize(
                    PascalStyleFormatInstruction.STRING,
                    1
                )
            }
        )
    assert not warnings_list


def test_check_dict_length_incorrect_type():
    with pytest.warns(UserWarning, match='a should be of class int'):
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            {
                'a': 'string'
            },
            {
                'a': PascalStyleFormatInstructionStringLengthSize(
                    PascalStyleFormatInstruction.MPINT,
                    1
                )
            }
        )
