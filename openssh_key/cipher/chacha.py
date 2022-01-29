from cryptography.hazmat.primitives import ciphers, poly1305
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from openssh_key.utils import readonly_static_property

from .common import AEADCipher


class ChaCha20Poly1305Cipher(AEADCipher):
    @classmethod
    def get_block_size(cls) -> int:
        return 8

    @classmethod
    def get_key_length(cls) -> int:
        return 64

    @classmethod
    def get_iv_length(cls) -> int:
        return 0

    @classmethod
    def get_tag_length(cls) -> int:
        return 16

    @classmethod
    def get_chacha20_key_length(cls) -> int:
        return cls.KEY_LENGTH // 2

    CHACHA20_KEY_LENGTH = readonly_static_property(get_chacha20_key_length)

    @classmethod
    def get_chacha20_initial_counter_nonce(cls) -> bytes:
        return b'\x00' * 16

    CHACHA20_INITIAL_COUNTER_NONCE = readonly_static_property(
        get_chacha20_initial_counter_nonce
    )

    @classmethod
    def get_chacha20_cipher_text_block_size(cls) -> int:
        return 64

    CHACHA20_CIPHER_TEXT_BLOCK_SIZE = readonly_static_property(
        get_chacha20_cipher_text_block_size
    )

    @classmethod
    def get_poly1305_key_length(cls) -> int:
        return 32

    POLY1305_KEY_LENGTH = readonly_static_property(get_poly1305_key_length)

    # Cannot use cryptography.hazmat.primitives.aead.ChaCha20Poly1305
    # since it follows RFC 7539 / 8439 in adding padding and encoding lengths,
    # which OpenSSH does not do

    @classmethod
    def encrypt_with_key_iv(
        cls,
        plain_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        # The first half of cipher_key encrypts the cipher_bytes
        # The second half encrypts the additional data
        # In OpenSSH, private keys do not have additional data,
        # so we discard the second half

        cipher_key_first_half = cipher_key[:cls.CHACHA20_KEY_LENGTH]

        encryptor: CipherContext = ciphers.Cipher(
            algorithms.ChaCha20(
                cipher_key_first_half,
                cls.CHACHA20_INITIAL_COUNTER_NONCE
            ),
            mode=None
        ).encryptor()  # type: ignore[no-untyped-call]

        # The ChaCha20 block counter starts at 0
        # Obtain the first block by encrypting 64 zero bytes
        # Then truncate to obtain the 32-byte Poly1305 key
        poly1305_key = encryptor.update(
            b'\x00' * cls.CHACHA20_CIPHER_TEXT_BLOCK_SIZE
        )[:cls.POLY1305_KEY_LENGTH]

        # After having encrypted one full block, the ChaCha20 block counter
        # is now 1. Encrypt the remaining cipher_bytes
        cipher_bytes_without_tag = encryptor.update(plain_bytes)

        tag = poly1305.Poly1305.generate_tag(
            poly1305_key,
            cipher_bytes_without_tag
        )

        return cipher_bytes_without_tag + tag

    @classmethod
    def decrypt_with_key_iv(
        cls,
        cipher_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        # The first half of cipher_key encrypts the cipher_bytes
        # The second half encrypts the additional data
        # In OpenSSH, private keys do not have additional data,
        # so we discard the second half

        cipher_key_first_half = cipher_key[:cls.CHACHA20_KEY_LENGTH]

        cipher_bytes_without_tag = cipher_bytes[:-cls.TAG_LENGTH]
        tag = cipher_bytes[-cls.TAG_LENGTH:]

        decryptor: CipherContext = ciphers.Cipher(
            algorithms.ChaCha20(
                cipher_key_first_half,
                cls.CHACHA20_INITIAL_COUNTER_NONCE
            ),
            mode=None
        ).decryptor()  # type: ignore[no-untyped-call]

        # The ChaCha20 block counter starts at 0
        # Obtain the first block by decrypting 64 zero bytes,
        # then truncate to obtain the 32-byte Poly1305 key
        poly1305_key = decryptor.update(
            b'\x00' * cls.CHACHA20_CIPHER_TEXT_BLOCK_SIZE
        )[:cls.POLY1305_KEY_LENGTH]
        poly1305.Poly1305.verify_tag(
            poly1305_key,
            cipher_bytes_without_tag,
            tag
        )

        # After having decrypted one full block, the ChaCha20 block counter
        # is now 1. Decrypt the remaining cipher_bytes
        return decryptor.update(cipher_bytes_without_tag)
