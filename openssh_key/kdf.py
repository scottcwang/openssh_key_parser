"""Classes representing key derivation functions.

The abstract base class is :py:class:`KDF`.
"""

import abc
import secrets
import types
import typing

import bcrypt

from openssh_key import utils
from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleFormatInstruction)

KDFOptionsTypeVar = typing.TypeVar(
    'KDFOptionsTypeVar',
    bound='KDFOptions'
)


class KDFOptions(utils.BaseDict, abc.ABC):
    """The parameters of a password-based key derivation function.

    Used to obtain a pseudorandom symmetric key by cryptographically hashing
    a potentially low-entropy passphrase given certain parameters, such as a
    work factor, memory factor, or salt.
    """

    @abc.abstractmethod
    def derive_key(self, passphrase: str, length: int) -> bytes:
        """Derives a key derivation function result from a given passphrase
        and parameters.

        Args:
            options
                Key derivation function parameters.
            passphrase
                Passphrase from which to derive key.

        Returns:
            Key derivation function result.
        """
        return b''

    __OPTIONS_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ]

    @classmethod
    @abc.abstractmethod
    def get_options_format_instructions_dict(cls) -> FormatInstructionsDict:
        """The Pascal-style byte stream format instructions for the parameters
        to a key derivation function.
        """
        return types.MappingProxyType(
            KDFOptions.__OPTIONS_FORMAT_INSTRUCTIONS_DICT
        )

    OPTIONS_FORMAT_INSTRUCTIONS_DICT = utils.readonly_static_property(
        get_options_format_instructions_dict
    )
    """The Pascal-style byte stream format instructions for the parameters
    to a key derivation function.
    """

    @classmethod
    @abc.abstractmethod
    def generate_options(
        cls: typing.Type[KDFOptionsTypeVar],
        **kwargs: typing.Any
    ) -> KDFOptionsTypeVar:
        """Generates parameters to be consumed by a key derivation function.

        Args:
            kwargs
                Keyword arguments using which to generate parameters.

        Returns:
            Generated key generation function parameters.
        """
        return cls({})


NoneKDFTypeVar = typing.TypeVar(
    'NoneKDFTypeVar',
    bound='NoneKDF'
)


class NoneKDF(KDFOptions):
    """Null key derivation function.

    To be used only with null encryption.
    """

    def derive_key(self, passphrase: str, length: int) -> bytes:
        """Returns an empty key derivation function result for use with null
        encryption.

        Args:
            options
                Ignored.
            passphrase
                Ignored.

        Returns:
            An empty key derivation function result.
        """
        return b''

    __OPTIONS_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {}
    """Empty format instructions.
    """

    @classmethod
    def get_options_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            NoneKDF.__OPTIONS_FORMAT_INSTRUCTIONS_DICT
        )

    @classmethod
    def generate_options(
        cls: typing.Type[NoneKDFTypeVar],
        **kwargs: typing.Any
    ) -> NoneKDFTypeVar:
        """Empty key derivation function parameters.

        Returns:
            An empty ``dict``.
        """
        return cls({})


BcryptKDFTypeVar = typing.TypeVar(
    'BcryptKDFTypeVar',
    bound='BcryptKDF'
)


class BcryptKDF(KDFOptions):
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

    __OPTIONS_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {
        'salt': PascalStyleFormatInstruction.BYTES,
        'rounds': '>I'
    }
    """The Pascal-style byte stream format instructions for the parameters
    to bcrypt-PBKDF2.
    """

    @classmethod
    def get_options_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            BcryptKDF.__OPTIONS_FORMAT_INSTRUCTIONS_DICT
        )

    @classmethod
    def generate_options(
        cls: typing.Type[BcryptKDFTypeVar],
        **kwargs: typing.Any
    ) -> BcryptKDFTypeVar:
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


_KDF_MAPPING = {
    'none': NoneKDF,
    'bcrypt': BcryptKDF
}


def create_kdf(kdf_type: str) -> typing.Type[KDFOptions]:
    """Returns the class corresponding to the given key derivation function
    type name.

    Args:
        kdf_type
            The name of the OpenSSH private key key derivation function type.

    Returns:
        The subclass of :py:class:`KDF` corresponding to the key derivation
        function type name.

    Raises:
        KeyError: There is no subclass of :py:class:`KDF` corresponding to
            the given key derivation function type name.
    """
    return _KDF_MAPPING[kdf_type]
