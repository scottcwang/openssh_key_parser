import warnings
import abc
import secrets
import typing

import bcrypt  # type: ignore

from openssh_key.pascal_style_byte_stream import (
    PascalStyleFormatInstruction,
    FormatInstructionsDict,
    ValuesDict
)


KDFTypeVar = typing.TypeVar(
    'KDFTypeVar',
    bound='KDF'
)

KDFOptions = ValuesDict


class KDFResult(typing.NamedTuple):
    cipher_key: bytes
    initialization_vector: bytes


class KDF(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def derive_key(options: KDFOptions, passphrase: str) -> KDFResult:
        return KDFResult(
            cipher_key=b'',
            initialization_vector=b''
        )

    @staticmethod
    @abc.abstractmethod
    def options_format_instructions_dict() -> FormatInstructionsDict:
        return {}

    @classmethod
    @abc.abstractmethod
    def generate_options(
        cls: typing.Type[KDFTypeVar],
        **kwargs: typing.Any
    ) -> KDFOptions:
        return {}


class NoneKDF(KDF):
    @staticmethod
    def derive_key(options: KDFOptions, passphrase: str) -> KDFResult:
        return KDFResult(
            cipher_key=b'',
            initialization_vector=b''
        )

    @staticmethod
    def options_format_instructions_dict() -> FormatInstructionsDict:
        return {}

    @classmethod
    def generate_options(
        cls: typing.Type['NoneKDF'],
        **kwargs: typing.Any
    ) -> KDFOptions:
        return {}


class BcryptKDF(KDF):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    SALT_LENGTH = 16
    ROUNDS = 16

    @staticmethod
    def derive_key(options: KDFOptions, passphrase: str) -> KDFResult:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            bcrypt_result = bcrypt.kdf(
                password=passphrase.encode(),
                salt=options['salt'],
                # https://blog.rebased.pl/2020/03/24/basic-key-security.html
                desired_key_bytes=BcryptKDF.KEY_LENGTH + BcryptKDF.IV_LENGTH,
                rounds=options['rounds']
            )
        return KDFResult(
            cipher_key=bcrypt_result[:BcryptKDF.KEY_LENGTH],
            initialization_vector=bcrypt_result[-BcryptKDF.IV_LENGTH:]
        )

    @staticmethod
    def options_format_instructions_dict() -> FormatInstructionsDict:
        return {
            'salt': PascalStyleFormatInstruction.BYTES,
            'rounds': '>I'
        }

    @classmethod
    def generate_options(
        cls: typing.Type['BcryptKDF'],
        **kwargs: typing.Any
    ) -> KDFOptions:
        return {
            'salt': secrets.token_bytes(
                kwargs['salt_length'] if 'salt_length' in kwargs
                else cls.SALT_LENGTH
            ),
            'rounds': (
                kwargs['rounds'] if 'rounds' in kwargs
                else cls.ROUNDS
            )
        }


_KDF_MAPPING = {
    'none': NoneKDF,
    'bcrypt': BcryptKDF
}


def create_kdf(kdf_type: str) -> typing.Type[KDF]:
    return _KDF_MAPPING[kdf_type]
