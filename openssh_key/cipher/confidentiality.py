import abc
import typing

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from openssh_key import utils

from .common import InitializationVectorCipher


class ConfidentialityOnlyCipher(InitializationVectorCipher, abc.ABC):
    @classmethod
    @abc.abstractmethod
    def get_mode(cls) -> typing.Callable[[bytes], modes.Mode]:
        raise NotImplementedError()

    MODE = utils.readonly_static_property(get_mode)

    @classmethod
    @abc.abstractmethod
    def get_algorithm(cls) -> typing.Callable[[bytes], ciphers.CipherAlgorithm]:
        raise NotImplementedError()

    ALGORITHM = utils.readonly_static_property(get_algorithm)

    @classmethod
    def _get_cipher(
        cls,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> ciphers.Cipher:
        return ciphers.Cipher(
            (cls.ALGORITHM)(cipher_key),
            (cls.MODE)(initialization_vector)
        )

    @classmethod
    def encrypt_with_key_iv(
        cls,
        plain_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        # https://github.com/pyca/cryptography/issues/6083
        encryptor: CipherContext = cls._get_cipher(
            cipher_key,
            initialization_vector
        ).encryptor()  # type: ignore[no-untyped-call]
        return encryptor.update(plain_bytes) + encryptor.finalize()

    @classmethod
    def decrypt_with_key_iv(
        cls,
        cipher_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        decryptor: CipherContext = cls._get_cipher(
            cipher_key,
            initialization_vector
        ).decryptor()  # type: ignore[no-untyped-call]
        return decryptor.update(cipher_bytes) + decryptor.finalize()


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
