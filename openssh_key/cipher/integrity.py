"""
Classes representing symmetric-key ciphers that offer guarantees of
confidentiality (secrecy) and integrity (authentication).
"""

import abc

from cryptography.hazmat.primitives import ciphers, poly1305
from cryptography.hazmat.primitives.ciphers import aead, algorithms
from cryptography.hazmat.primitives.ciphers.base import CipherContext
from openssh_key import utils

from .common import InitializationVectorCipher


class ConfidentialityIntegrityCipher(InitializationVectorCipher, abc.ABC):
    """A symmetric-key cipher that offers guarantees of confidentiality
    (secrecy) and integrity (authentication).
    """
    @classmethod
    @abc.abstractmethod
    def get_tag_length(cls) -> int:
        """The length of the authentication tag of this cipher in bytes.

        In OpenSSH private keys, the tag's length is not included as part of
        the length of the Pascal-style cipher byte string. The
        :py:func:`ConfidentialityIntegrityCipher.encrypt` method appends the
        tag to the end of the returned cipher byte string, and the caller
        should separate it. Analogously, the
        :py:func:`ConfidentialityIntegrityCipher.decrypt` method requires that
        the caller append the tag to the cipher byte string.
        """
        return 0

    TAG_LENGTH = utils.readonly_static_property(get_tag_length)
    """The length of the authentication tag of this cipher in bytes.

    In OpenSSH private keys, the tag's length is not included as part of
    the length of the Pascal-style cipher byte string. The
    :py:func:`ConfidentialityIntegrityCipher.encrypt` method appends the
    tag to the end of the returned cipher byte string, and the caller
    should separate it. Analogously, the
    :py:func:`ConfidentialityIntegrityCipher.decrypt` method requires that
    the caller first append the tag to the cipher byte string.
    """


class AES_GCMCipher(ConfidentialityIntegrityCipher, abc.ABC):
    """The Advanced Encryption Standard (the Rijndael block cipher), under the
    Galois/Counter Mode of operation (GCM) initialized with a given
    initialization vector.
    """

    @classmethod
    def get_iv_length(cls) -> int:
        """The value 12, the length in bytes of the initialization vector
        for AES-GCM.
        """
        return 12

    @classmethod
    def get_tag_length(cls) -> int:
        """The value 16, the length in bytes of the tag for GCM.
        """
        return 16

    @classmethod
    def get_block_size(cls) -> int:
        """The value 16, the cipher block size of AES.
        """
        return 16

    @classmethod
    def encrypt_with_key_iv(
        cls,
        plain_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        return aead.AESGCM(cipher_key).encrypt(
            initialization_vector,
            plain_bytes,
            None
        )

    @classmethod
    def decrypt_with_key_iv(
        cls,
        cipher_bytes: bytes,
        cipher_key: bytes,
        initialization_vector: bytes
    ) -> bytes:
        return aead.AESGCM(cipher_key).decrypt(
            initialization_vector,
            cipher_bytes,
            None
        )


class AES128_GCMCipher(AES_GCMCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 128 bits, under the Galois/Counter Mode of operation (GCM)
    initialized with a given initialization vector.
    """

    @classmethod
    def get_key_length(cls) -> int:
        """The value 16, the length in bytes of the cipher key.
        """
        return 16


class AES256_GCMCipher(AES_GCMCipher):
    """The Advanced Encryption Standard (the Rijndael block cipher) with a key
    length of 256 bits, under the Galois/Counter Mode of operation (GCM)
    initialized with a given initialization vector.
    """

    @classmethod
    def get_key_length(cls) -> int:
        """The value 32, the length in bytes of the cipher key.
        """
        return 32


class ChaCha20Poly1305Cipher(ConfidentialityIntegrityCipher):
    """The ChaCha20 encryption algorithm with a Poly1305 authentication tag.

    When encrypting private keys, OpenSSH uses only the first 32 bytes of the
    64-byte key derived from the key derivation function as the ChaCha20
    encryption key; then it proceeds as in
    `RFC 8439 section 2.8 <https://datatracker.ietf.org/doc/html/rfc8439#section-2.8>`_,
    except that:

    * the nonce is replaced by the constant byte string of sixteen zero bytes
    * there are no additional authenticated data
    * the Poly1305 authentication tag is computed on a message that consists of
      only the ciphertext (in particular, OpenSSH does not add padding or
      encode message lengths to compute the Poly1305 authentication tag).
    """

    @classmethod
    def get_block_size(cls) -> int:
        """The value 8, the block size in bytes of the ChaCha20Poly1305 cipher
        for padding ciphertext.
        """
        return 8

    @classmethod
    def get_key_length(cls) -> int:
        """The value 64, the length in bytes of the key obtained from the key
        derivation function.

        OpenSSH uses only the first 32 bytes as the ChaCha20 encryption key.
        """
        return 64

    @classmethod
    def get_iv_length(cls) -> int:
        """The value 0.

        When encrypting private keys, OpenSSH replaces the ChaCha20 nonce by
        the constant byte string consisting of sixteen zero bytes. Therefore,
        no initialization vector needs to be obtained from the key derivation
        function.
        """
        return 0

    @classmethod
    def get_tag_length(cls) -> int:
        """The value 16, the Poly1305 tag length in bytes.
        """
        return 16

    @classmethod
    def get_chacha20_key_length(cls) -> int:
        """The value 32, the length in bytes of the ChaCha20 encryption key.
        """
        return cls.KEY_LENGTH // 2

    CHACHA20_KEY_LENGTH = utils.readonly_static_property(
        get_chacha20_key_length)
    """The value 32, the length in bytes of the ChaCha20 encryption key.
    """

    @classmethod
    def get_chacha20_initial_counter_nonce(cls) -> bytes:
        """The byte string consisting of sixteen zero bytes.

        When encrypting private keys, OpenSSH replaces the ChaCha20 nonce by
        the constant byte string consisting of sixteen zero bytes. Therefore,
        no initialization vector needs to be obtained from the key derivation
        function.
        """
        return b'\x00' * 16

    CHACHA20_INITIAL_COUNTER_NONCE = utils.readonly_static_property(
        get_chacha20_initial_counter_nonce
    )
    """The byte string consisting of sixteen zero bytes.

    When encrypting private keys, OpenSSH replaces the ChaCha20 nonce by
    the constant byte string consisting of sixteen zero bytes. Therefore,
    no initialization vector needs to be obtained from the key derivation
    function.
    """

    @classmethod
    def get_chacha20_cipher_text_block_size(cls) -> int:
        """The value 64, the block size in bytes of the ChaCha20 encryption
        algorithm.
        """
        return 64

    CHACHA20_CIPHER_TEXT_BLOCK_SIZE = utils.readonly_static_property(
        get_chacha20_cipher_text_block_size
    )
    """The value 64, the block size in bytes of the ChaCha20 encryption
    algorithm.
    """

    @classmethod
    def get_poly1305_key_length(cls) -> int:
        """The value 32, the length in bytes of the Poly1305 key.
        """
        return 32

    POLY1305_KEY_LENGTH = utils.readonly_static_property(
        get_poly1305_key_length)
    """The value 32, the length in bytes of the Poly1305 key.
    """

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
        ).encryptor()

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
        ).decryptor()

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
