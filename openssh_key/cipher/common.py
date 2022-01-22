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

    @staticmethod
    @abc.abstractmethod
    def get_block_size() -> int:
        """The block size for this cipher.
        """
        return 0

    BLOCK_SIZE = utils.readonly_static_property(get_block_size)
    """The block size for this cipher.
    """
