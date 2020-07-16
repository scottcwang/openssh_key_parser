import base64

import pytest
import bcrypt

from openssh_key.kdf import create_kdf, NoneKDF, BcryptKDF
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction


def test_factory_none():
    assert isinstance(create_kdf('none'), NoneKDF.__class__)


def test_factory_bcrypt():
    assert isinstance(create_kdf('bcrypt'), BcryptKDF.__class__)


def test_none_options_format_instructions_dict():
    assert NoneKDF.options_format_instructions_dict() == {}


def test_bcrypt_options_format_instructions_dict():
    assert BcryptKDF.options_format_instructions_dict() == {
        'salt': PascalStyleFormatInstruction.BYTES,
        'rounds': '>I'
    }


def test_none():
    test_key = 'abcd'
    assert NoneKDF.derive_key({}, test_key) == {
        'cipher_key': b'',
        'initialization_vector': b''
    }


def test_bcrypt_calls_lib(mocker):
    mocker.patch('bcrypt.kdf')

    passphrase = 'abcd'
    options = {
        'salt': b'\x00',
        'rounds': 1
    }
    BcryptKDF.derive_key(options, passphrase)
    bcrypt.kdf.assert_called_once_with(
        password=passphrase.encode(),
        salt=options['salt'],
        desired_key_bytes=BcryptKDF.IV_LENGTH+BcryptKDF.KEY_LENGTH,
        rounds=options['rounds']
    )


def test_bcrypt_returns_key_iv(mocker):
    def mock_bcrypt_kdf(password, salt, desired_key_bytes, rounds):
        return b'\x00' * BcryptKDF.KEY_LENGTH + b'\x01' * BcryptKDF.IV_LENGTH
    mocker.patch('bcrypt.kdf', mock_bcrypt_kdf)

    passphrase = 'abcd'
    options = {
        'salt': b'\x00',
        'rounds': 1
    }
    key_iv = BcryptKDF.derive_key(options, passphrase)
    assert key_iv == {
        'cipher_key': b'\x00' * BcryptKDF.KEY_LENGTH,
        'initialization_vector': b'\x01' * BcryptKDF.IV_LENGTH
    }
