"""Classes representing symmetric-key ciphers.

The abstract base class is :py:class:`Cipher`.
"""

import abc
import typing

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import CipherContext

from openssh_key import utils
from openssh_key.kdf import KDFResult


class Cipher(abc.ABC):
    """An abstract symmetric-key cipher.

    Used to encrypt and decrypt private plaintext bytes of a length that is a
    multiple of a cipher-specific block size, given a key and an
    initialization vector.
    """
    @staticmethod
    @abc.abstractmethod
    def encrypt(
        kdf_result: KDFResult,
        plain_bytes: bytes
    ) -> bytes:
        """Encrypts the given plaintext bytes using the given result from a
        key derivation function.

        Args:
            kdf_result
                The result of a key derivation function.
            plain_bytes
                Plaintext bytes to be encrypted.

        Returns:
            Ciphertext bytes.
        """

    @staticmethod
    @abc.abstractmethod
    def decrypt(
        kdf_result: KDFResult,
        cipher_bytes: bytes
    ) -> bytes:
        """Decrypts the given ciphertext bytes using the given result from a
        key derivation function.

        Args:
            kdf_result
                The result of a key derivation function.
            cipher_bytes
                Ciphertext bytes to be decrypted.

        Returns:
            Plaintext bytes.
        """

    @staticmethod
    @abc.abstractmethod
    def get_block_size() -> int:
        """The block size for this cipher.
        """
        return 0

    BLOCK_SIZE = utils.readonly_static_property(get_block_size)
    """The block size for this cipher.
    """


class NoneCipher(Cipher):
    """Null encryption.
    """
    @staticmethod
    def encrypt(
        kdf_result: KDFResult,
        plain_bytes: bytes
    ) -> bytes:
        """Returns the plaintext bytes as given.

        Args:
            kdf_result
                Ignored.
            plain_bytes
                Plaintext bytes to be returned.

        Returns:
            The given plaintext bytes.
        """
        return plain_bytes

    @staticmethod
    def decrypt(
        kdf_result: KDFResult,
        cipher_bytes: bytes
    ) -> bytes:
        """Returns the ciphertext bytes as given.

        Args:
            kdf_result
                Ignored.
            cipher_bytes
                Ciphertext bytes to be returned.

        Returns:
            The given ciphertext bytes.
        """
        return cipher_bytes

    @staticmethod
    def get_block_size() -> int:
        """The value 8, the cipher block size
        `OpenSSH uses <https://github.com/openssh/openssh-portable/blob/9cd40b829a5295cc81fbea8c7d632b2478db6274/cipher.c#L112>`_
        to pad private bytes under null encryption.
        """
        return 8


class AES256_CTRCipher(Cipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 256 bits, under the counter mode of operation initialized with a
    given initialization vector.
    """
    @staticmethod
    def encrypt(
        kdf_result: KDFResult,
        plain_bytes: bytes
    ) -> bytes:
        """Encrypts the given plaintext bytes using the given key and
        initialization vector.

        Args:
            kdf_result
                The result of a key derivation function.
            plain_bytes
                Plaintext bytes to be encrypted.

        Raises:
            ValueError: The key length is not one of 128, 192, 256, 512 bits,
                or the initialization vector is not of length 128 bits.

        Returns:
            Ciphertext bytes.
        """
        cipher = ciphers.Cipher(
            algorithms.AES(kdf_result.cipher_key),
            modes.CTR(kdf_result.initialization_vector)
        )
        # https://github.com/pyca/cryptography/issues/6083
        encryptor: CipherContext = cipher.encryptor()  # type: ignore[no-untyped-call]
        return encryptor.update(plain_bytes) + encryptor.finalize()

    @staticmethod
    def decrypt(
        kdf_result: KDFResult,
        cipher_bytes: bytes
    ) -> bytes:
        """Decrypts the given ciphertext bytes using the given key and
        initialization vector.

        Args:
            kdf_result
                The result of a key derivation function.
            cipher_bytes
                Ciphertext bytes to be decrypted.

        Raises:
            ValueError: The key length is not one of 128, 192, 256, 512 bits,
                or the initialization vector is not of length 128 bits.

        Returns:
            Plaintext bytes.
        """
        cipher = ciphers.Cipher(
            algorithms.AES(kdf_result.cipher_key),
            modes.CTR(kdf_result.initialization_vector)
        )
        decryptor: CipherContext = cipher.decryptor()  # type: ignore[no-untyped-call]
        return decryptor.update(cipher_bytes) + decryptor.finalize()

    @staticmethod
    def get_block_size() -> int:
        """The value 16, the cipher block size of AES.
        """
        return 16


_CIPHER_MAPPING = {
    'none': NoneCipher,
    'aes256-ctr': AES256_CTRCipher
}


def create_cipher(cipher_type: str) -> typing.Type[Cipher]:
    """Returns the class corresponding to the given cipher type name.

    Args:
        cipher_type
            The name of the OpenSSH private key cipher type.

    Returns:
        The subclass of :py:class:`Cipher` corresponding to the cipher type
        name.

    Raises:
        KeyError: There is no subclass of :py:class:`Cipher` corresponding to
            the given cipher type name.
    """
    return _CIPHER_MAPPING[cipher_type]
