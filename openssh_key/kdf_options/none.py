"""
Classes representing the null key derivation function.
"""

import types
import typing

from openssh_key.pascal_style_byte_stream import FormatInstructionsDict

from .common import KDFOptions

NoneKDFOptionsTypeVar = typing.TypeVar(
    'NoneKDFOptionsTypeVar',
    bound='NoneKDFOptions'
)


class NoneKDFOptions(KDFOptions):
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

    __FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {}
    """Empty format instructions.
    """

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            NoneKDFOptions.__FORMAT_INSTRUCTIONS_DICT
        )

    @classmethod
    def generate_options(
        cls: typing.Type[NoneKDFOptionsTypeVar],
        **kwargs: typing.Any
    ) -> NoneKDFOptionsTypeVar:
        """Empty key derivation function parameters.

        Returns:
            An empty ``dict``.
        """
        return cls({})
