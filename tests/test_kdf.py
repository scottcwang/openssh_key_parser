import base64

import pytest

from openssh_key.kdf import create_kdf, NoneKDF, BcryptKDF


def test_factory_none():
    assert isinstance(create_kdf('none')['kdf'], NoneKDF.__class__)


def test_factory_bcrypt():
    assert isinstance(create_kdf('bcrypt')['kdf'], BcryptKDF.__class__)


def test_none():
    test_key = 'abcd'
    assert NoneKDF.derive_key({}, test_key) == {
        'cipher_key': b'',
        'initialization_vector': b''
    }

