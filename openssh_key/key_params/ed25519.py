"""
Classes representing Ed25519 keys.
"""

import types
import typing
import warnings

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519 as cryptography_ed25519
from openssh_key import utils
from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleFormatInstruction,
                                                  ValuesDict)

from .common import ConversionFunctions, PrivateKeyParams, PublicKeyParams


class Ed25519PublicKeyParams(PublicKeyParams):
    """The parameters comprising a key in the Edwards-curve Digital Signature
    Algorithm elliptic-curve cryptosystem on SHA-512 and Curve25519.

    The names and iteration order of parameters of a *public* Ed25519 key is:

    * ``public``: The public key (:any:`bytes`).

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A parameter value from the above list is missing from
            ``params`` or does not have the correct type, or the key size is
            not valid for Ed25519 (32 bytes).
    """
    __FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[FormatInstructionsDict] = {
        'public': PascalStyleFormatInstruction.BYTES
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            Ed25519PublicKeyParams.__FORMAT_INSTRUCTIONS_DICT
        )

    @staticmethod
    def get_key_size() -> int:
        """
        The value 32, the key size, in bytes, of an Ed25519 key.
        """
        return 32

    KEY_SIZE = utils.readonly_static_property(get_key_size)
    """
    The value 32, the key size, in bytes, of an Ed25519 key.
    """

    def check_params_are_valid(self) -> None:
        """Checks whether the values within this parameters object conform to
        the format instructions, and whether the key size is valid for Ed25519
        (32 bytes).

        Raises:
            UserWarning: A parameter value is missing or does not have a type
                that matches the format instructions for this key type, or the
                key size is incorrect.
        """
        super().check_params_are_valid()
        if 'public' not in self or type(self['public']) != bytes:
            return
        if len(self['public']) != self.KEY_SIZE:
            warnings.warn('Public key not of length ' + str(self.KEY_SIZE))

    @classmethod
    def conversion_functions(
        cls
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Conversion functions for key objects of the following types:

        * :any:`cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`
        * :any:`nacl.signing.VerifyKey` (if ``nacl`` can be imported)
        * :any:`bytes`

        Returns:
            A :py:class:`typing.Mapping` from the above types of key objects
            to functions that take key objects of these types and return
            parameter values.
        """
        def ed25519_public_key_convert_from_cryptography(
            key_object: cryptography_ed25519.Ed25519PublicKey
        ) -> ValuesDict:
            return {
                'public': key_object.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            }

        def ed25519_public_key_convert_to_cryptography(
            key_params: ValuesDict
        ) -> cryptography_ed25519.Ed25519PublicKey:
            return cryptography_ed25519.Ed25519PublicKey.from_public_bytes(
                key_params['public']
            )

        def ed25519_public_key_convert_from_bytes(
            key_object: bytes
        ) -> ValuesDict:
            return {
                'public': key_object
            }

        def ed25519_public_key_convert_to_bytes(
            key_params: ValuesDict
        ) -> bytes:
            return bytes(key_params['public'])

        conversion_functions_dict: typing.MutableMapping[
            typing.Type[typing.Any],
            ConversionFunctions
        ] = {
            cryptography_ed25519.Ed25519PublicKey: ConversionFunctions(
                ed25519_public_key_convert_from_cryptography,
                ed25519_public_key_convert_to_cryptography
            ),
            bytes: ConversionFunctions(
                ed25519_public_key_convert_from_bytes,
                ed25519_public_key_convert_to_bytes
            )
        }

        try:
            import nacl.signing as nacl_signing

            def ed25519_public_key_convert_from_pynacl(
                key_object: nacl_signing.VerifyKey
            ) -> ValuesDict:
                return {
                    'public': bytes(key_object)
                }

            def ed25519_public_key_convert_to_pynacl(
                key_params: ValuesDict
            ) -> nacl_signing.VerifyKey:
                return nacl_signing.VerifyKey(key_params['public'])

            conversion_functions_dict[
                nacl_signing.VerifyKey
            ] = ConversionFunctions(
                ed25519_public_key_convert_from_pynacl,
                ed25519_public_key_convert_to_pynacl
            )
        except ImportError:
            pass

        return conversion_functions_dict


Ed25519PrivateKeyParamsTypeVar = typing.TypeVar(
    'Ed25519PrivateKeyParamsTypeVar',
    bound='Ed25519PrivateKeyParams'
)


class Ed25519PrivateKeyParams(PrivateKeyParams, Ed25519PublicKeyParams):
    """The parameters comprising a private key in the Edwards-curve Digital
    Signature Algorithm elliptic-curve cryptosystem on SHA-512 and Curve25519.

    The names and iteration order of parameters of a *private* Ed25519 key is:

    * ``public``: The public key (:any:`bytes`).
    * ``private_public``: The seed of the private key, followed by the public
        key (:any:`bytes`).

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A parameter value from the above list is missing from
            ``params`` or does not have the correct type, the key size is
            not valid for Ed25519 (32 bytes), or the public portion of the
            ``private_public`` parameter value does not match the ``public``
            parameter value.
    """

    __FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[FormatInstructionsDict] = {
        'public': PascalStyleFormatInstruction.BYTES,
        'private_public': PascalStyleFormatInstruction.BYTES
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            Ed25519PrivateKeyParams.__FORMAT_INSTRUCTIONS_DICT
        )

    def check_params_are_valid(self) -> None:
        """Checks whether the values within this parameters object conform to
        the format instructions, whether the key sizes are valid for Ed25519
        (32 bytes each for the private and public keys), and whether the
        public portion of the ``private_public`` parameter matches the
        ``public`` parameter.

        Raises:
            UserWarning: A parameter value is missing or does not have a type
                that matches the format instructions for this key type, the
                key sizes are incorrect, or the parameters do not match.
        """
        Ed25519PublicKeyParams.check_params_are_valid(self)
        PrivateKeyParams.check_params_are_valid(self)
        if 'private_public' not in self or type(self['private_public']) != bytes \
                or 'public' not in self or type(self['public']) != bytes:
            return
        if self['private_public'][self.KEY_SIZE:] \
                != self['public']:
            warnings.warn('Public key does not match')
        if len(self['private_public'][self.KEY_SIZE:]) != self.KEY_SIZE:
            warnings.warn(
                'Private key not of length ' + str(self.KEY_SIZE)
            )

    @classmethod
    def generate_private_params(
        cls: typing.Type[Ed25519PrivateKeyParamsTypeVar],
        **kwargs: typing.Any
    ) -> Ed25519PrivateKeyParamsTypeVar:
        """Constructs and initializes an Ed25519 private key parameters object
        with generated values.

        Args:
            kwargs
                Keyword arguments consumed to generate parameter values.

        Returns:
            A private key parameters object with generated values valid for
            an Ed25519 private key (the key size is 32 bytes).
        """

        private_key = cryptography_ed25519.Ed25519PrivateKey.generate()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return cls({
            'public': public_bytes,
            'private_public': private_bytes + public_bytes
        })

    @classmethod
    def conversion_functions(
        cls
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Conversion functions for key objects of the following types:

        * :any:`cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`
        * :any:`nacl.signing.SigningKey` (if ``nacl`` can be imported)
        * :any:`bytes` (the private bytes only)

        Returns:
            A :py:class:`typing.Mapping` from the above types of key objects
            to functions that take key objects of these types and return
            parameter values.
        """
        def ed25519_private_key_convert_from_cryptography(
            key_object: cryptography_ed25519.Ed25519PrivateKey
        ) -> ValuesDict:
            private_bytes = key_object.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_bytes = key_object.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return {
                'public': public_bytes,
                'private_public': private_bytes + public_bytes
            }

        def ed25519_private_key_convert_to_cryptography(
            key_params: ValuesDict
        ) -> cryptography_ed25519.Ed25519PrivateKey:
            return cryptography_ed25519.Ed25519PrivateKey.from_private_bytes(
                key_params[
                    'private_public'
                ][:Ed25519PrivateKeyParams.KEY_SIZE]
            )

        def ed25519_private_key_convert_from_bytes(
            key_object: bytes
        ) -> ValuesDict:
            private_bytes = key_object
            public_bytes = cryptography_ed25519.Ed25519PrivateKey.from_private_bytes(
                key_object
            ).public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return {
                'public': public_bytes,
                'private_public': private_bytes + public_bytes
            }

        def ed25519_private_key_convert_to_bytes(
            key_params: ValuesDict
        ) -> bytes:
            return bytes(
                key_params[
                    'private_public'
                ][: Ed25519PrivateKeyParams.KEY_SIZE]
            )

        conversion_functions_dict: typing.MutableMapping[
            typing.Type[typing.Any],
            ConversionFunctions
        ] = {
            cryptography_ed25519.Ed25519PrivateKey: ConversionFunctions(
                ed25519_private_key_convert_from_cryptography,
                ed25519_private_key_convert_to_cryptography
            ),
            bytes: ConversionFunctions(
                ed25519_private_key_convert_from_bytes,
                ed25519_private_key_convert_to_bytes
            )
        }

        try:
            import nacl.signing as nacl_signing

            def ed25519_private_key_convert_from_pynacl(
                key_object: nacl_signing.SigningKey
            ) -> ValuesDict:
                private_bytes = bytes(key_object)
                public_bytes = bytes(key_object.verify_key)
                return {
                    'public': public_bytes,
                    'private_public': private_bytes + public_bytes
                }

            def ed25519_private_key_convert_to_pynacl(
                key_params: ValuesDict
            ) -> nacl_signing.SigningKey:
                return nacl_signing.SigningKey(
                    key_params[
                        'private_public'
                    ][:Ed25519PrivateKeyParams.KEY_SIZE]
                )

            conversion_functions_dict[
                nacl_signing.SigningKey
            ] = ConversionFunctions(
                ed25519_private_key_convert_from_pynacl,
                ed25519_private_key_convert_to_pynacl
            )
        except ImportError:
            pass

        return conversion_functions_dict
