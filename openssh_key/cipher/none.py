"""
Classes representing null encryption.
"""

from openssh_key.kdf_options import KDFOptions

from .common import Cipher


class NoneCipher(Cipher):
    """Null encryption.
    """
    @classmethod
    def encrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
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

    @classmethod
    def decrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
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

    @classmethod
    def get_block_size(cls) -> int:
        """The value 8, the cipher block size
        `OpenSSH uses <https://github.com/openssh/openssh-portable/blob/9cd40b829a5295cc81fbea8c7d632b2478db6274/cipher.c#L112>`_
        to pad private bytes under null encryption.
        """
        return 8
