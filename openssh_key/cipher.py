import abc
import typing

import cryptography.hazmat.primitives.ciphers as ciphers
import cryptography.hazmat.primitives.ciphers.algorithms as algorithms
import cryptography.hazmat.primitives.ciphers.modes as modes
from cryptography.hazmat.backends import default_backend


class Cipher(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def encrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        plain_bytes: bytes
    ) -> bytes:
        pass

    @staticmethod
    @abc.abstractmethod
    def decrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        cipher_bytes: bytes
    ) -> bytes:
        pass

    @staticmethod
    @abc.abstractmethod
    def block_size() -> int:
        pass


class NoneCipher(Cipher):
    @staticmethod
    def encrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        plain_bytes: bytes
    ) -> bytes:
        return plain_bytes

    @staticmethod
    def decrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        cipher_bytes: bytes
    ) -> bytes:
        return cipher_bytes

    BLOCK_SIZE = 8

    @staticmethod
    def block_size() -> int:
        return NoneCipher.BLOCK_SIZE


class AES256_CTRCipher(Cipher):
    @staticmethod
    def encrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        plain_bytes: bytes
    ) -> bytes:
        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(plain_bytes) + encryptor.finalize()

    @staticmethod
    def decrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        cipher_bytes: bytes
    ) -> bytes:
        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(cipher_bytes) + decryptor.finalize()

    BLOCK_SIZE = 16

    @staticmethod
    def block_size() -> int:
        return AES256_CTRCipher.BLOCK_SIZE


_CIPHER_MAPPING = {
    'none': NoneCipher,
    'aes256-ctr': AES256_CTRCipher
}


def create_cipher(cipher_type: str) -> typing.Type[Cipher]:
    return _CIPHER_MAPPING[cipher_type]
