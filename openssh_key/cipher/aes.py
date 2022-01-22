from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from openssh_key import utils
from openssh_key.kdf_options import KDFOptions

from .common import Cipher


class AES256_CTRCipher(Cipher):
    @staticmethod
    def get_key_length() -> int:
        return 32

    KEY_LENGTH = utils.readonly_static_property(get_key_length)

    @staticmethod
    def get_iv_length() -> int:
        return 16

    IV_LENGTH = utils.readonly_static_property(get_iv_length)

    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 256 bits, under the counter mode of operation initialized with a
    given initialization vector.
    """
    @classmethod
    def encrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
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
        kdf_result = kdf.derive_key(passphrase, cls.KEY_LENGTH + cls.IV_LENGTH)

        cipher_key = kdf_result[:cls.KEY_LENGTH]
        initialization_vector = kdf_result[-cls.IV_LENGTH:]

        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector)
        )
        # https://github.com/pyca/cryptography/issues/6083
        # type: ignore[no-untyped-call]
        encryptor: CipherContext = cipher.encryptor()
        return encryptor.update(plain_bytes) + encryptor.finalize()

    @classmethod
    def decrypt(
        cls,
        kdf: KDFOptions,
        passphrase: str,
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
        kdf_result = kdf.derive_key(passphrase, cls.KEY_LENGTH + cls.IV_LENGTH)

        cipher_key = kdf_result[:cls.KEY_LENGTH]
        initialization_vector = kdf_result[-cls.IV_LENGTH:]

        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector)
        )
        # type: ignore[no-untyped-call]
        decryptor: CipherContext = cipher.decryptor()
        return decryptor.update(cipher_bytes) + decryptor.finalize()

    @staticmethod
    def get_block_size() -> int:
        """The value 16, the cipher block size of AES.
        """
        return 16
