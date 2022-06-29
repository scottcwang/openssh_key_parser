"""
Classes representing symmetric-key ciphers that offer only a guarantee of
confidentiality (secrecy).
"""

import abc
import typing

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from openssh_key import utils

from .common import InitializationVectorCipher


class ConfidentialityOnlyCipher(InitializationVectorCipher, abc.ABC):
    """A symmetric-key cipher that offers only a guarantee of confidentiality
    (secrecy).
    """
    @classmethod
    @abc.abstractmethod
    def get_mode(cls) -> typing.Callable[[bytes], modes.Mode]:
        """The mode of operation of this cipher.
        """
        def r(_: bytes) -> modes.Mode:
            raise NotImplementedError('returned from abstract method')
        return r

    MODE = utils.readonly_static_property(get_mode)
    """The mode of operation of this cipher.
    """

    @classmethod
    @abc.abstractmethod
    def get_algorithm(cls) -> typing.Callable[[bytes], ciphers.CipherAlgorithm]:
        """The encryption algorithm of this cipher.
        """
        def r(_: bytes) -> ciphers.CipherAlgorithm:
            raise NotImplementedError('returned from abstract method')
        return r

    ALGORITHM = utils.readonly_static_property(get_algorithm)
    """The encryption algorithm of this cipher.
    """

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
        encryptor: CipherContext = cls._get_cipher(
            cipher_key,
            initialization_vector
        ).encryptor()
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
        ).decryptor()
        return decryptor.update(cipher_bytes) + decryptor.finalize()


class AESCipher(ConfidentialityOnlyCipher, abc.ABC):
    """The Advanced Encryption Standard (the Rijndael block cipher),
    under a mode of operation that offers only confidentiality.
    """

    @classmethod
    def get_block_size(cls) -> int:
        """The value 16, the cipher block size of AES.
        """
        return 16

    @classmethod
    def get_algorithm(cls) -> typing.Callable[[bytes], ciphers.CipherAlgorithm]:
        """The AES encryption algorithm.
        """
        # pylint: disable=unnecessary-lambda
        return lambda cipher_key: algorithms.AES(
            cipher_key
        )


class CTRCipher(ConfidentialityOnlyCipher, abc.ABC):
    """A cipher under the counter mode of operation.
    """

    @classmethod
    def get_mode(cls) -> typing.Callable[[bytes], modes.Mode]:
        """The counter mode of operation.
        """
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
        """The value 16, the length in bytes of the cipher key.
        """
        return 16


class AES192_CTRCipher(AESCipher, CTRCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 192 bits, under the counter mode of operation initialized with a
    given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        """The value 24, the length in bytes of the cipher key.
        """
        return 24


class AES256_CTRCipher(AESCipher, CTRCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 256 bits, under the counter mode of operation initialized with a
    given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        """The value 32, the length in bytes of the cipher key.
        """
        return 32


class CBCCipher(ConfidentialityOnlyCipher, abc.ABC):
    """A cipher under the cipher block chaining mode of operation.
    """

    @classmethod
    def get_mode(cls) -> typing.Callable[[bytes], modes.Mode]:
        """The cipher block chaining mode of operation.
        """
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
        """The value 16, the length in bytes of the cipher key.
        """
        return 16


class AES192_CBCCipher(AESCipher, CBCCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 192 bits, under the cipher block chaining mode of operation
    initialized with a given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        """The value 24, the length in bytes of the cipher key.
        """
        return 24


class AES256_CBCCipher(AESCipher, CBCCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 256 bits, under the cipher block chaining mode of operation
    initialized with a given initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        """The value 32, the length in bytes of the cipher key.
        """
        return 32


class TripleDESCipher(ConfidentialityOnlyCipher, abc.ABC):
    """The Triple Data Encryption Algorithm (3DES).

    NIST `has deprecated <https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA>`_
    this encryption algorithm since 2017.
    """

    @classmethod
    def get_block_size(cls) -> int:
        """The value 8, the cipher block size of Triple DES.
        """
        return 8

    @classmethod
    def get_algorithm(cls) -> typing.Callable[[bytes], ciphers.CipherAlgorithm]:
        """The Triple Data Encryption Algorithm.
        """
        # pylint: disable=unnecessary-lambda
        return lambda cipher_key: algorithms.TripleDES(
            cipher_key
        )


class TripleDES_CBCCipher(TripleDESCipher, CBCCipher):
    """The Triple Data Encryption Algorithm with a key length of 192 bits,
    under the cipher block chaining mode of operation initialized with a given
    initialization vector.
    """

    @staticmethod
    def get_key_length() -> int:
        """The value 24, the length in bytes of the three concatenated cipher
        keys used by 3DES.
        """
        return 24
