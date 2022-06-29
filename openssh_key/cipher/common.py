"""
Classes representing symmetric-key ciphers.
"""

import abc

from openssh_key import utils
from openssh_key.kdf_options import KDFOptions


class Cipher(abc.ABC):
    """An abstract symmetric-key cipher.

    Used to encrypt and decrypt private plaintext bytes of a length that is a
    multiple of a cipher-specific block size, given a key and an
    initialization vector.
    """
    @classmethod
    @abc.abstractmethod
    def encrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
        plain_bytes: bytes
    ) -> bytes:
        """Encrypts the given plaintext bytes using the given options of a
        key derivation function and the given passphrase to derive the
        encryption key.

        Args:
            kdf
                The options of a key derivation function.
            passphrase
                The passphrase from which the cipher key is derived.
            plain_bytes
                Plaintext bytes to be encrypted.

        Returns:
            Ciphertext bytes.
        """

    @classmethod
    @abc.abstractmethod
    def decrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
        cipher_bytes: bytes
    ) -> bytes:
        """Decrypts the given ciphertext bytes using the given options of a
        key derivation function and the given passphrase to derive the
        encryption key.

        Args:
            kdf
                The options of a key derivation function.
            passphrase
                The passphrase from which the cipher key is derived.
            cipher_bytes
                Ciphertext bytes to be decrypted.

        Returns:
            Plaintext bytes.
        """

    @classmethod
    @abc.abstractmethod
    def get_block_size(cls) -> int:
        """The block size for this cipher.
        """
        return 0

    BLOCK_SIZE = utils.readonly_static_property(get_block_size)
    """The block size for this cipher.
    """


class InitializationVectorCipher(Cipher, abc.ABC):
    """A cipher that takes an initialization vector as input.
    """

    @classmethod
    @abc.abstractmethod
    def get_key_length(cls) -> int:
        """The key length for this cipher in bytes.
        """
        return 0

    KEY_LENGTH = utils.readonly_static_property(get_key_length)
    """The key length for this cipher in bytes.
    """

    @classmethod
    @abc.abstractmethod
    def get_iv_length(cls) -> int:
        """The initialization vector length for this cipher in bytes.
        Defaults to the block size.
        """
        return cls.BLOCK_SIZE

    IV_LENGTH = utils.readonly_static_property(get_iv_length)
    """The initialization vector length for this cipher in bytes.
    Defaults to the block size.
    """

    @classmethod
    @abc.abstractmethod
    def encrypt_with_key_iv(
        cls,
        plain_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        """Encrypts the given plaintext bytes using the given cipher key and
        initialization vector.

        Args:
            plain_bytes
                Plaintext bytes to be encrypted.
            cipher_key
                The cipher key.
            initialization_vector
                The initialization vector. For some ciphers, this need only
                be a nonce.

        Returns:
            Ciphertext bytes.
        """
        raise NotImplementedError('abstract method')

    @classmethod
    @abc.abstractmethod
    def decrypt_with_key_iv(
        cls,
        cipher_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        """Decrypts the given ciphertext bytes using the given cipher key and
        initialization vector.

        Args:
            cipher_bytes
                Ciphertext bytes to be encrypted.
            cipher_key
                The cipher key.
            initialization_vector
                The initialization vector. For some ciphers, this need only
                be a nonce.

        Returns:
            Plaintext bytes.
        """
        raise NotImplementedError('abstract method')

    @classmethod
    def encrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
        plain_bytes: bytes
    ) -> bytes:
        kdf_result = kdf.derive_key(passphrase, cls.KEY_LENGTH + cls.IV_LENGTH)

        cipher_key = kdf_result[:cls.KEY_LENGTH]
        initialization_vector = kdf_result[-cls.IV_LENGTH:]

        return cls.encrypt_with_key_iv(plain_bytes, cipher_key, initialization_vector)

    @classmethod
    def decrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
        cipher_bytes: bytes
    ) -> bytes:
        kdf_result = kdf.derive_key(passphrase, cls.KEY_LENGTH + cls.IV_LENGTH)

        cipher_key = kdf_result[:cls.KEY_LENGTH]
        initialization_vector = kdf_result[-cls.IV_LENGTH:]

        return cls.decrypt_with_key_iv(
            cipher_bytes,
            cipher_key,
            initialization_vector
        )
