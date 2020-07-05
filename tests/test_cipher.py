import pytest

from openssh_key.cipher import create_cipher, NoneCipher, AES256_CTRCipher


def test_factory_none():
    assert isinstance(create_cipher('none'), NoneCipher.__class__)


def test_factory_aes256_ctr():
    assert isinstance(create_cipher('aes256-ctr'), AES256_CTRCipher.__class__)


def test_none_encrypt():
    test_bytes = b'abcd'
    assert NoneCipher.encrypt(None, None, test_bytes) == test_bytes


def test_none_decrypt():
    test_bytes = b'abcd'
    assert NoneCipher.decrypt(None, None, test_bytes) == test_bytes


