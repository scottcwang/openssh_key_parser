import abc

import bcrypt

from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction


class KDF(abc.ABC):  # pragma: no cover
    @staticmethod
    @abc.abstractmethod
    def derive_key(options, passphrase):
        pass


class NoneKDF(KDF):
    @staticmethod
    def derive_key(options, passphrase):
        return {
            'cipher_key': b'',
            'initialization_vector': b''
        }


class BcryptKDF(KDF):
    KEY_LENGTH = 32
    IV_LENGTH = 16

    @staticmethod
    def derive_key(options, passphrase):
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


_KDF_MAPPING = {
    'none': {
        'kdf': NoneKDF,
        'options_format': {'': '0s'}
    },
    'bcrypt': {
        'kdf': BcryptKDF,
        'options_format': {
            'salt': PascalStyleFormatInstruction.BYTES,
            'rounds': '>I'
        }
    }
}


def create_kdf(type):
    return _KDF_MAPPING[type]
