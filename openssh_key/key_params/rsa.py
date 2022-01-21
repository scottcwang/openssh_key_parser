"""
Classes representing RSA keys.
"""


import types
import typing

from cryptography.hazmat.primitives.asymmetric import rsa as cryptography_rsa
from openssh_key import utils
from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleFormatInstruction,
                                                  ValuesDict)

from .common import ConversionFunctions, PrivateKeyParams, PublicKeyParams


class RSAPublicKeyParams(PublicKeyParams):
    """The parameters comprising a key in the Rivest-Shamir-Adleman (RSA)
    cryptosystem.

    The names and iteration order of parameters of a *public* RSA key is:

    * ``e``: The public exponent (:any:`int`).
    * ``n``: The public composite modulus (:any:`int`).

    NB: OpenSSH `will deprecate <https://www.openssh.com/txt/release-8.2>`_
    the "ssh-rsa" public key *signature algorithm*, due to its use of the
    insecure SHA-1 hash algorithm, in favour of the "rsa-sha-256" and
    "rsa-sha-512" signature algorithms, which use the secure SHA-2 hash
    algorithms. The "ssh-rsa" *keys* represented by this class work with all
    of these signature algorithms, as per
    `RFC 8332 <https://tools.ietf.org/html/rfc8332#section-3>`_.

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A parameter value from the above list is missing from
            ``params`` or does not have the correct type.
    """
    __FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[FormatInstructionsDict] = {
        'e': PascalStyleFormatInstruction.MPINT,
        'n': PascalStyleFormatInstruction.MPINT,
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            RSAPublicKeyParams.__FORMAT_INSTRUCTIONS_DICT
        )

    @classmethod
    def conversion_functions(
        cls
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Conversion functions for key objects of the following types:

        * :any:`cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`

        Returns:
            A :py:class:`typing.Mapping` from the above types of key objects
            to functions that take key objects of these types and return
            parameter values.
        """
        def rsa_public_key_convert_from_cryptography(
            key_object: cryptography_rsa.RSAPublicKey
        ) -> ValuesDict:
            public_numbers = key_object.public_numbers()
            return {
                'e': public_numbers.e,
                'n': public_numbers.n
            }

        def rsa_public_key_convert_to_cryptography(
            key_params: ValuesDict
        ) -> cryptography_rsa.RSAPublicKey:
            return cryptography_rsa.RSAPublicNumbers(
                key_params['e'],
                key_params['n']
            ).public_key()

        return {
            cryptography_rsa.RSAPublicKey: ConversionFunctions(
                rsa_public_key_convert_from_cryptography,
                rsa_public_key_convert_to_cryptography
            )
        }


RSAPrivateKeyParamsTypeVar = typing.TypeVar(
    'RSAPrivateKeyParamsTypeVar',
    bound='RSAPrivateKeyParams'
)


class RSAPrivateKeyParams(PrivateKeyParams, RSAPublicKeyParams):
    """The parameters comprising a private key in the Rivest-Shamir-Adleman
    (RSA) cryptosystem.

    The names and iteration order of parameters of a *private* RSA key is:

    * ``n``: The public composite modulus (:any:`int`).
    * ``e``: The public exponent (:any:`int`; NB order of ``n`` and ``e`` are
        reversed relative to :any:`RSAPublicKeyParams`).
    * ``d``: The private exponent (:any:`int`).
    * ``iqmp``: ``q^-1 mod p`` (:any:`int`).
    * ``p``: First prime comprising ``n`` (:any:`int`).
    * ``q``: Second prime comprising ``n`` (:any:`int`).

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A parameter value from the above list is missing from
            ``params`` or does not have the correct type.
    """
    __FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[FormatInstructionsDict] = {
        'n': PascalStyleFormatInstruction.MPINT,
        'e': PascalStyleFormatInstruction.MPINT,
        'd': PascalStyleFormatInstruction.MPINT,
        'iqmp': PascalStyleFormatInstruction.MPINT,
        'p': PascalStyleFormatInstruction.MPINT,
        'q': PascalStyleFormatInstruction.MPINT
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            RSAPrivateKeyParams.__FORMAT_INSTRUCTIONS_DICT
        )

    @staticmethod
    def get_public_exponent() -> int:
        """
        The value 65537, the default public exponent of an RSA key.
        """
        return 65537

    PUBLIC_EXPONENT = utils.readonly_static_property(get_public_exponent)
    """
    The value 65537, the default public exponent of an RSA key.
    """

    @staticmethod
    def get_key_size() -> int:
        """
        The value 4096, the default key size, in bits, of an RSA key.
        """
        return 4096
    
    KEY_SIZE = utils.readonly_static_property(get_key_size)
    """
    The value 4096, the default key size, in bits, of an RSA key.
    """

    @classmethod
    def generate_private_params(
        cls: typing.Type[RSAPrivateKeyParamsTypeVar],
        **kwargs: typing.Any
    ) -> RSAPrivateKeyParamsTypeVar:
        """Constructs and initializes an RSA private key parameters object with
        generated values.

        Args:
            kwargs
                Keyword arguments consumed to generate parameter values.

        Returns:
            A private key parameters object with generated values valid for
            an RSA private key. Following OpenSSH, if ``kwargs['e']``
            is not given, a public exponent of 65537 is used, and if
            ``kwargs['key_size']`` is not given, a key of length 4096 is
            generated.
        """
        private_key = cryptography_rsa.generate_private_key(
            public_exponent=(
                kwargs['e'] if 'e' in kwargs else cls.PUBLIC_EXPONENT
            ),
            key_size=(
                kwargs['key_size'] if 'key_size' in kwargs else cls.KEY_SIZE
            )
        )
        private_key_numbers = private_key.private_numbers()
        return cls(
            {
                'n': private_key_numbers.public_numbers.n,
                'e': private_key_numbers.public_numbers.e,
                'd': private_key_numbers.d,
                'iqmp': private_key_numbers.iqmp,
                'p': private_key_numbers.p,
                'q': private_key_numbers.q
            }
        )

    @classmethod
    def conversion_functions(
        cls
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Conversion functions for key objects of the following types:

        * :any:`cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`

        Returns:
            A :py:class:`typing.Mapping` from the above types of key objects
            to functions that take key objects of these types and return
            parameter values.
        """
        def rsa_private_key_convert_from_cryptography(
            key_object: cryptography_rsa.RSAPrivateKey
        ) -> ValuesDict:
            private_numbers = key_object.private_numbers()
            return {
                'n': private_numbers.public_numbers.n,
                'e': private_numbers.public_numbers.e,
                'd': private_numbers.d,
                'iqmp': private_numbers.iqmp,
                'p': private_numbers.p,
                'q': private_numbers.q
            }

        def rsa_private_key_convert_to_cryptography(
            key_params: ValuesDict
        ) -> cryptography_rsa.RSAPrivateKey:
            return cryptography_rsa.RSAPrivateNumbers(
                key_params['p'],
                key_params['q'],
                key_params['d'],
                cryptography_rsa.rsa_crt_dmp1(
                    key_params['d'], key_params['p']),
                cryptography_rsa.rsa_crt_dmp1(
                    key_params['d'], key_params['q']),
                key_params['iqmp'],
                cryptography_rsa.RSAPublicNumbers(
                    key_params['e'],
                    key_params['n']
                )
            ).private_key()

        return {
            cryptography_rsa.RSAPrivateKey: ConversionFunctions(
                rsa_private_key_convert_from_cryptography,
                rsa_private_key_convert_to_cryptography
            )
        }
