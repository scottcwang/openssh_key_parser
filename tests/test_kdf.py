import bcrypt
import pytest
from openssh_key.kdf_options import (BcryptKDFOptions, NoneKDFOptions,
                                     get_kdf_options_class)
from openssh_key.pascal_style_byte_stream import (PascalStyleByteStream,
                                                  PascalStyleFormatInstruction)


def test_factory_none():
    assert get_kdf_options_class('none') == NoneKDFOptions


def test_factory_bcrypt():
    assert get_kdf_options_class('bcrypt') == BcryptKDFOptions


def test_none_format_instructions_dict():
    assert NoneKDFOptions.FORMAT_INSTRUCTIONS_DICT == {}


def test_none_generate_options():
    assert NoneKDFOptions.generate_options() == {}


def test_bcrypt_format_instructions_dict():
    assert BcryptKDFOptions.FORMAT_INSTRUCTIONS_DICT == {
        'salt': PascalStyleFormatInstruction.BYTES,
        'rounds': '>I'
    }


def test_bcrypt_generate_options():
    options = BcryptKDFOptions.generate_options()
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            options,
            BcryptKDFOptions.FORMAT_INSTRUCTIONS_DICT
        )
    assert not warnings_list
    assert len(options['salt']) == BcryptKDFOptions.SALT_LENGTH
    assert options['rounds'] == BcryptKDFOptions.ROUNDS


def test_bcrypt_generate_options_salt_length():
    salt_length = 32
    options = BcryptKDFOptions.generate_options(salt_length=salt_length)
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            options,
            BcryptKDFOptions.FORMAT_INSTRUCTIONS_DICT
        )
    assert not warnings_list
    assert len(options['salt']) == salt_length
    assert options['rounds'] == BcryptKDFOptions.ROUNDS


def test_bcrypt_generate_options_rounds():
    rounds = 32
    options = BcryptKDFOptions.generate_options(rounds=rounds)
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            options,
            BcryptKDFOptions.FORMAT_INSTRUCTIONS_DICT
        )
    assert not warnings_list
    assert len(options['salt']) == BcryptKDFOptions.SALT_LENGTH
    assert options['rounds'] == rounds


def test_none():
    test_key = 'abcd'
    assert NoneKDFOptions({}).derive_key(test_key, 0) == b''


def test_bcrypt_calls_lib(mocker):
    mocker.patch('bcrypt.kdf')

    passphrase = 'abcd'
    options = {
        'salt': b'\x00',
        'rounds': 1
    }
    BcryptKDFOptions(options).derive_key(passphrase, 48)
    bcrypt.kdf.assert_called_once_with(  # pylint: disable=no-member
        password=passphrase.encode(),
        salt=options['salt'],
        desired_key_bytes=48,
        rounds=options['rounds'],
        ignore_few_rounds=True
    )
