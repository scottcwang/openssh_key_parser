import warnings
import abc
import secrets

import bcrypt

from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction


class KDF(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def derive_key(options, passphrase):
        pass

    @staticmethod
    @abc.abstractmethod
    def options_format_instructions_dict():
        return {}

    @classmethod
    @abc.abstractmethod
    def generate_options(cls, **kwargs):
        return {}


class NoneKDF(KDF):
    @staticmethod
    def derive_key(options, passphrase):
        return {
            'cipher_key': b'',
            'initialization_vector': b''
        }

    @staticmethod
    def options_format_instructions_dict():
        return {}

    @classmethod
    def generate_options(cls, **kwargs):
        return {}


class BcryptKDF(KDF):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    SALT_LENGTH = 16
    ROUNDS = 16

    @staticmethod
    def derive_key(options, passphrase):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            bcrypt_result = bcrypt.kdf(
                password=passphrase.encode(),
                salt=options['salt'],
                # https://blog.rebased.pl/2020/03/24/basic-key-security.html
                desired_key_bytes=BcryptKDF.KEY_LENGTH + BcryptKDF.IV_LENGTH,
                rounds=options['rounds']
            )
        return {
            'cipher_key': bcrypt_result[:BcryptKDF.KEY_LENGTH],
            'initialization_vector': bcrypt_result[-BcryptKDF.IV_LENGTH:]
        }

    @staticmethod
    def options_format_instructions_dict():
        return {
            'salt': PascalStyleFormatInstruction.BYTES,
            'rounds': '>I'
        }

    @classmethod
    def generate_options(cls, salt_length=None, rounds=None, **kwargs):
        if salt_length is None:
            salt_length = cls.SALT_LENGTH
        if rounds is None:
            rounds = cls.ROUNDS
        return {
            'salt': secrets.token_bytes(salt_length),
            'rounds': rounds
        }


_KDF_MAPPING = {
    'none': NoneKDF,
    'bcrypt': BcryptKDF
}


def create_kdf(kdf_type):
    return _KDF_MAPPING[kdf_type]
