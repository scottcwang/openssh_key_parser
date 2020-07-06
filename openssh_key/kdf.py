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
    @staticmethod
    def derive_key(options, passphrase):
        bcrypt_result = bcrypt.kdf(
            password=passphrase.encode(),
            salt=options['salt'],
            desired_key_bytes=32+16,  # https://blog.rebased.pl/2020/03/24/basic-key-security.html
            rounds=options['rounds']
        )
        return {
            'cipher_key': bcrypt_result[:32],
            'initialization_vector': bcrypt_result[-16:]
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
