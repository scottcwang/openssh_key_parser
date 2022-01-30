"""
Classes representing key derivation function options.
"""

import abc
import types
import typing

from openssh_key import utils
from openssh_key.pascal_style_byte_stream import FormatInstructionsDict

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
