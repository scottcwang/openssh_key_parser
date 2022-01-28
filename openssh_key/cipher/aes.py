import abc
import typing

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import aead, algorithms, modes

from .common import AEADCipher, ConfidentialityOnlyCipher


class AESCipher(ConfidentialityOnlyCipher, abc.ABC):
    @classmethod
    def get_block_size(cls) -> int:
        """The value 16, the cipher block size of AES.
        """
        return 16

    @classmethod
    def get_algorithm(cls) -> typing.Callable[[bytes], ciphers.CipherAlgorithm]:
        # pylint: disable=unnecessary-lambda
        return lambda cipher_key: algorithms.AES(
            cipher_key
        )


class CTRCipher(ConfidentialityOnlyCipher, abc.ABC):
    @classmethod
    def get_mode(cls) -> typing.Callable[[bytes], modes.Mode]:
        # pylint: disable=unnecessary-lambda
        return lambda initialization_vector: modes.CTR(
            initialization_vector
        )


class AES128_CTRCipher(AESCipher, CTRCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 128 bits, under the counter mode of operation initialized with a
    given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        return 16


class AES192_CTRCipher(AESCipher, CTRCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 192 bits, under the counter mode of operation initialized with a
    given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        return 24


class AES256_CTRCipher(AESCipher, CTRCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 256 bits, under the counter mode of operation initialized with a
    given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        return 32


class CBCCipher(ConfidentialityOnlyCipher, abc.ABC):
    @classmethod
    def get_mode(cls) -> typing.Callable[[bytes], modes.Mode]:
        # pylint: disable=unnecessary-lambda
        return lambda initialization_vector: modes.CBC(
            initialization_vector
        )


class AES128_CBCCipher(AESCipher, CBCCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 128 bits, under the cipher block chaining mode of operation
    initialized with a given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        return 16


class AES192_CBCCipher(AESCipher, CBCCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 192 bits, under the cipher block chaining mode of operation
    initialized with a given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        return 24


class AES256_CBCCipher(AESCipher, CBCCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 256 bits, under the cipher block chaining mode of operation
    initialized with a given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        return 32


class AES_GCMCipher(AEADCipher, abc.ABC):
    @classmethod
    def get_iv_length(cls) -> int:
        return 12

    @classmethod
    def get_tag_length(cls) -> int:
        return 16

    @classmethod
    def get_block_size(cls) -> int:
        return 16

    @classmethod
    def encrypt_with_key_iv(
        cls,
        plain_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        return aead.AESGCM(cipher_key).encrypt(
            initialization_vector,
            plain_bytes,
            None
        )

    @classmethod
    def decrypt_with_key_iv(
        cls,
        cipher_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        return aead.AESGCM(cipher_key).decrypt(
            initialization_vector,
            cipher_bytes,
            None
        )


class AES128_GCMCipher(AES_GCMCipher):
    @classmethod
    def get_key_length(cls) -> int:
        return 16


class AES256_GCMCipher(AES_GCMCipher):
    @classmethod
    def get_key_length(cls) -> int:
        return 32
