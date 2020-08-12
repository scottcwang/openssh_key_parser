"""Classes representing symmetric-key ciphers.

The abstract base class is :py:class:`Cipher`.
"""

import abc
import typing

import cryptography.hazmat.primitives.ciphers as ciphers
import cryptography.hazmat.primitives.ciphers.algorithms as algorithms
import cryptography.hazmat.primitives.ciphers.modes as modes
from cryptography.hazmat.backends import default_backend


class Cipher(abc.ABC):
    """An abstract symmetric-key cipher.

    Used to encrypt and decrypt private plaintext bytes of a length that is a
    multiple of a cipher-specific block size, given a key and an
    initialization vector.
    """
    @staticmethod
    @abc.abstractmethod
    def encrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        plain_bytes: bytes
    ) -> bytes:
        """Encrypts the given plaintext bytes using the given key and
        initialization vector.

        Args:
            cipher_key
                Symmetric key.
            initialization_vector
                Cipher initialization vector.
            plain_bytes
                Plaintext bytes to be encrypted.

        Returns:
            Ciphertext bytes.
        """

    @staticmethod
    @abc.abstractmethod
    def decrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        cipher_bytes: bytes
    ) -> bytes:
        """Decrypts the given ciphertext bytes using the given key and
        initialization vector.

        Args:
            cipher_key
                Symmetric key.
            initialization_vector
                Cipher initialization vector.
            cipher_bytes
                Ciphertext bytes to be decrypted.

        Returns:
            Plaintext bytes.
        """

    BLOCK_SIZE: typing.ClassVar[int]
    """The block size for this cipher.
    """


class NoneCipher(Cipher):
    """Null encryption.
    """
    @staticmethod
    def encrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        plain_bytes: bytes
    ) -> bytes:
        """Returns the plaintext bytes as given.

        Args:
            cipher_key
                Ignored.
            initialization_vector
                Ignored.
            plain_bytes
                Plaintext bytes to be returned.

        Returns:
            The given plaintext bytes.
        """
        return plain_bytes

    @staticmethod
    def decrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        cipher_bytes: bytes
    ) -> bytes:
        """Returns the ciphertext bytes as given.

        Args:
            cipher_key
                Ignored.
            initialization_vector
                Ignored.
            cipher_bytes
                Ciphertext bytes to be returned.

        Returns:
            The given ciphertext bytes.
        """
        return cipher_bytes

    BLOCK_SIZE: typing.ClassVar[int] = 8
    """The value 8, the cipher block size
    `OpenSSH uses <https://github.com/openssh/openssh-portable/blob/9cd40b829a5295cc81fbea8c7d632b2478db6274/cipher.c#L112>`_
    to pad private bytes under null encryption.
    """


class AES256_CTRCipher(Cipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 256 bits, under the counter mode of operation initialized with a
    given initialization vector.
    """
    @staticmethod
    def encrypt(
        cipher_key: bytes,
        initialization_vector: bytes,
        plain_bytes: bytes
    ) -> bytes:
        """Encrypts the given plaintext bytes using the given key and
        initialization vector.

        Args:
            cipher_key
                Symmetric key.
            initialization_vector
                Cipher initialization vector.
            plain_bytes
                Plaintext bytes to be encrypted.

        Raises:
            ValueError: The key length is not one of 128, 192, 256, 512 bits,
                or the initialization vector is not of length 128 bits.

        Returns:
            Ciphertext bytes.
        """
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
        """Decrypts the given ciphertext bytes using the given key and
        initialization vector.

        Args:
            cipher_key
                Symmetric key.
            initialization_vector
                Cipher initialization vector.
            cipher_bytes
                Ciphertext bytes to be decrypted.

        Raises:
            ValueError: The key length is not one of 128, 192, 256, 512 bits,
                or the initialization vector is not of length 128 bits.

        Returns:
            Plaintext bytes.
        """
        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(cipher_bytes) + decryptor.finalize()

    BLOCK_SIZE: typing.ClassVar[int] = 16
    """The value 16, the cipher block size of AES.
    """


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
