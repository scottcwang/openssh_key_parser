import abc

import cryptography.hazmat.primitives.ciphers as ciphers
import cryptography.hazmat.primitives.ciphers.algorithms as algorithms
import cryptography.hazmat.primitives.ciphers.modes as modes
from cryptography.hazmat.backends import default_backend


class Cipher(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def encrypt(cipher_key, initialization_vector, plain_bytes):
        pass

    @staticmethod
    @abc.abstractmethod
    def decrypt(cipher_key, initialization_vector, cipher_bytes):
        pass

    @staticmethod
    @abc.abstractmethod
    def block_size():
        pass


class NoneCipher(Cipher):
    @staticmethod
    def encrypt(cipher_key, initialization_vector, plain_bytes):
        return plain_bytes

    @staticmethod
    def decrypt(cipher_key, initialization_vector, cipher_bytes):
        return cipher_bytes

    @staticmethod
    def block_size():
        return 8


class AES256_CTRCipher(Cipher):
    @staticmethod
    def encrypt(cipher_key, initialization_vector, plain_bytes):
        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(plain_bytes) + encryptor.finalize()

    @staticmethod
    def decrypt(cipher_key, initialization_vector, cipher_bytes):
        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(cipher_bytes) + decryptor.finalize()

    @staticmethod
    def block_size():
        return 16


_CIPHER_MAPPING = {
    'none': NoneCipher,
    'aes256-ctr': AES256_CTRCipher
}


def create_cipher(type):
    return _CIPHER_MAPPING[type]
