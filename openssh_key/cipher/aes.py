import abc
import typing

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from .common import ConfidentialityOnlyCipher


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
