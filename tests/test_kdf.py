import bcrypt
import pytest
from openssh_key.kdf import BcryptKDF, KDFResult, NoneKDF, create_kdf
from openssh_key.pascal_style_byte_stream import (PascalStyleByteStream,
                                                  PascalStyleFormatInstruction)


def test_factory_none():
    assert create_kdf('none') == NoneKDF


def test_factory_bcrypt():
    assert create_kdf('bcrypt') == BcryptKDF


def test_none_options_format_instructions_dict():
    assert NoneKDF.OPTIONS_FORMAT_INSTRUCTIONS_DICT == {}


def test_none_generate_options():
    assert NoneKDF.generate_options() == {}


def test_bcrypt_options_format_instructions_dict():
    assert BcryptKDF.OPTIONS_FORMAT_INSTRUCTIONS_DICT == {
        'salt': PascalStyleFormatInstruction.BYTES,
        'rounds': '>I'
    }


def test_bcrypt_generate_options():
    options = BcryptKDF.generate_options()
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            options,
            BcryptKDF.OPTIONS_FORMAT_INSTRUCTIONS_DICT
        )
    assert not warnings_list
    assert len(options['salt']) == BcryptKDF.SALT_LENGTH
    assert options['rounds'] == BcryptKDF.ROUNDS


def test_bcrypt_generate_options_salt_length():
    salt_length = 32
    options = BcryptKDF.generate_options(salt_length=salt_length)
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            options,
            BcryptKDF.OPTIONS_FORMAT_INSTRUCTIONS_DICT
        )
    assert not warnings_list
    assert len(options['salt']) == salt_length
    assert options['rounds'] == BcryptKDF.ROUNDS


def test_bcrypt_generate_options_rounds():
    rounds = 32
    options = BcryptKDF.generate_options(rounds=rounds)
    with pytest.warns(None) as warnings_list:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            options,
            BcryptKDF.OPTIONS_FORMAT_INSTRUCTIONS_DICT
        )
    assert not warnings_list
    assert len(options['salt']) == BcryptKDF.SALT_LENGTH
    assert options['rounds'] == rounds


def test_none():
    test_key = 'abcd'
    assert NoneKDF.derive_key({}, test_key) == KDFResult(
        cipher_key=b'',
        initialization_vector=b''
    )


def test_bcrypt_calls_lib(mocker):
    mocker.patch('bcrypt.kdf')

    passphrase = 'abcd'
    options = {
        'salt': b'\x00',
        'rounds': 1
    }
    BcryptKDF.derive_key(options, passphrase)
    bcrypt.kdf.assert_called_once_with(  # pylint: disable=no-member
        password=passphrase.encode(),
        salt=options['salt'],
        desired_key_bytes=BcryptKDF.IV_LENGTH+BcryptKDF.KEY_LENGTH,
        rounds=options['rounds'],
        ignore_few_rounds=True
    )


def test_bcrypt_returns_key_iv(mocker):
    def mock_bcrypt_kdf(**_):
        return b'\x00' * BcryptKDF.KEY_LENGTH + b'\x01' * BcryptKDF.IV_LENGTH
    mocker.patch('bcrypt.kdf', mock_bcrypt_kdf)

    passphrase = 'abcd'
    options = {
        'salt': b'\x00',
        'rounds': 1
    }
    key_iv = BcryptKDF.derive_key(options, passphrase)
    assert key_iv == KDFResult(
        cipher_key=b'\x00' * BcryptKDF.KEY_LENGTH,
        initialization_vector=b'\x01' * BcryptKDF.IV_LENGTH
    )
