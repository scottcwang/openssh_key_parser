"""
Classes representing key derivation function options.
"""

import abc
import typing

from openssh_key.pascal_style_byte_stream import PascalStyleDict

KDFOptionsTypeVar = typing.TypeVar(
    'KDFOptionsTypeVar',
    bound='KDFOptions'
)


class KDFOptions(PascalStyleDict):
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
