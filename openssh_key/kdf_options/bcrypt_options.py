"""
Classes representing options for the Bcrypt-PBKDF2 key derivation function.
"""

import secrets
import types
import typing

from openssh_key import utils
from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleFormatInstruction)

import bcrypt

from .common import KDFOptions

BcryptKDFOptionsTypeVar = typing.TypeVar(
    'BcryptKDFOptionsTypeVar',
    bound='BcryptKDFOptions'
)


class BcryptKDFOptions(KDFOptions):
    """Bcrypt-PBKDF2, as implemented by OpenSSH; viz., the `RFC 2898
    Password-based Key Derivation Function 2 <https://tools.ietf.org/html/rfc2898#section-5.2>`_,
    using the Blowfish-cipher-based password hash function as the pseudorandom
    function.
    """

    @staticmethod
    def get_salt_length() -> int:
        return 16

    SALT_LENGTH = utils.readonly_static_property(get_salt_length)

    @staticmethod
    def get_rounds() -> int:
        return 16

    ROUNDS = utils.readonly_static_property(get_rounds)

    def derive_key(self, passphrase: str, length: int) -> bytes:
        """Derives a bcrypt-PBKDF2 result from a given passphrase and
        parameters.

        `OpenSSH uses <https://github.com/openssh/openssh-portable/blob/e073106f370cdd2679e41f6f55a37b491f0e82fe/sshkey.c#L3875>`_
        a hash length of 48 bytes: 32 for the symmetric key and 16 for the
        cipher initialization vector.

        Args:
            options
                Bcrypt-PBKDF2 parameters.
            passphrase
                Passphrase from which to derive key.

        Returns:
            Bcrypt-PBKDF2 result.

        Raises:
            ValueError: ``passphrase`` or ``options['salt']`` is empty, or
                ``options['rounds']`` is negative.
        """
        return bcrypt.kdf(
            password=passphrase.encode(),
            salt=self['salt'],
            desired_key_bytes=length,
            rounds=self['rounds'],
            ignore_few_rounds=True
        )

    __FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {
        'salt': PascalStyleFormatInstruction.BYTES,
        'rounds': '>I'
    }
    """The Pascal-style byte stream format instructions for the parameters
    to bcrypt-PBKDF2.
    """

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            BcryptKDFOptions.__FORMAT_INSTRUCTIONS_DICT
        )

    @classmethod
    def generate_options(
        cls: typing.Type[BcryptKDFOptionsTypeVar],
        **kwargs: typing.Any
    ) -> BcryptKDFOptionsTypeVar:
        """Generates parameters to be consumed by bcrypt-PBKDF2.

        Args:
            kwargs
                Keyword arguments using which to generate parameters.

        Returns:
            Generated key generation function parameters. Following OpenSSH,
            if ``kwargs['salt_length']`` is not given, a salt of length 16
            bytes is generated, and if ``kwargs['rounds']`` is not given, 16
            PBKDF2 rounds are used.
        """
        return cls({
            'salt': secrets.token_bytes(
                kwargs['salt_length'] if 'salt_length' in kwargs
                else cls.SALT_LENGTH
            ),
            'rounds': (
                kwargs['rounds'] if 'rounds' in kwargs
                else cls.ROUNDS
            )
        })
