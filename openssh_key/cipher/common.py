import abc
import typing

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.base import CipherContext
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

    @classmethod
    @abc.abstractmethod
    def decrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
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
    @classmethod
    @abc.abstractmethod
    def get_key_length(cls) -> int:
        raise NotImplementedError()

    KEY_LENGTH = utils.readonly_static_property(get_key_length)

    @classmethod
    @abc.abstractmethod
    def get_iv_length(cls) -> int:
        return cls.BLOCK_SIZE

    IV_LENGTH = utils.readonly_static_property(get_iv_length)

    @classmethod
    @abc.abstractmethod
    def encrypt_with_key_iv(
        cls,
        plain_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def decrypt_with_key_iv(
        cls,
        cipher_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        raise NotImplementedError()

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


class AEADCipher(InitializationVectorCipher, abc.ABC):
    @classmethod
    @abc.abstractmethod
    def get_tag_length(cls) -> int:
        raise NotImplementedError()

    TAG_LENGTH = utils.readonly_static_property(get_tag_length)
