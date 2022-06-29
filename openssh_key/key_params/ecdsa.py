"""
Classes representing ECDSA keys.
"""

import abc
import types
import typing
import warnings

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ObjectIdentifier
from openssh_key import utils
from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleFormatInstruction,
                                                  ValuesDict)

from .common import ConversionFunctions, PrivateKeyParams, PublicKeyParams


class ECDSAPublicKeyParams(PublicKeyParams, abc.ABC):
    """The parameters comprising a key in the Elliptic Curve Digital Signature
    Algorithm cryptosystem.

    The names and iteration order of parameters of a *public* ECDSA key are:

    * ``identifier``: The identifier of the elliptic curve domain parameters,
                      as specified in
                      `RFC 5656 <https://www.ietf.org/rfc/rfc5656.html#section-6.1>`_
                      (:any:`str`).
    * ``q``: The public key, the elliptic curve point encoded as described in
             `SEC 1 <https://www.secg.org/sec1-v2.pdf>`_ (:any:`bytes`).

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
        'identifier': PascalStyleFormatInstruction.STRING,
        'q': PascalStyleFormatInstruction.BYTES,
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            ECDSAPublicKeyParams.__FORMAT_INSTRUCTIONS_DICT
        )

    @staticmethod
    @abc.abstractmethod
    def get_curve_identifier() -> str:
        """The identifier, as specified in
        `RFC 5656 <https://www.ietf.org/rfc/rfc5656.html#section-6.1>`_,
        of a set of elliptic curve domain parameters.
        """
        return ''

    CURVE_IDENTIFIER = utils.readonly_static_property(get_curve_identifier)
    """The identifier, as specified in
    `RFC 5656 <https://www.ietf.org/rfc/rfc5656.html#section-6.1>`_,
    of a set of elliptic curve domain parameters.
    """

    @staticmethod
    @abc.abstractmethod
    def get_curve_name() -> str:
        """The name of the elliptic curve domain parameters that corresponds to
        ``CURVE_IDENTIFIER``.
        """
        return ''

    CURVE_NAME = utils.readonly_static_property(get_curve_name)
    """The name of the elliptic curve domain parameters that corresponds to
    ``CURVE_IDENTIFIER``.
    """

    @staticmethod
    @abc.abstractmethod
    def get_curve_oid() -> str:
        """The X.509 object identifier of the elliptic curve domain parameters that
        corresponds to ``CURVE_IDENTIFIER``.
        """
        return ''

    CURVE_OID = utils.readonly_static_property(get_curve_oid)
    """The X.509 object identifier of the elliptic curve domain parameters that
    corresponds to ``CURVE_IDENTIFIER``.
    """

    @classmethod
    def convert_from(cls, key_object: typing.Any) -> 'PublicKeyParams':
        if utils.is_abstract(cls):
            for subcls in cls.__subclasses__():
                if utils.is_abstract(subcls):  # Direct descendant classes only
                    continue
                try:
                    return subcls.convert_from(key_object)
                except ValueError:
                    pass
        return super().convert_from(key_object)

    @classmethod
    def conversion_functions(
        cls
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Conversion functions for key objects of the following types:

        * :any:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`

        Returns:
            A :py:class:`typing.Mapping` from the above types of key objects
            to functions that take key objects of these types and return
            parameter values.

        Raises:
            ValueError: the curve identifier encoded in the public key does not
                correspond to the key type
        """
        def ecdsa_public_key_convert_from_cryptography(
            key_object: ec.EllipticCurvePublicKey
        ) -> typing.Optional[ValuesDict]:
            if key_object.curve.name != cls.CURVE_NAME:
                return None
            public_bytes = key_object.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
            return {
                'identifier': cls.CURVE_IDENTIFIER,
                'q': public_bytes,
            }

        def ecdsa_public_key_convert_to_cryptography(
            key_params: ValuesDict
        ) -> typing.Optional[ec.EllipticCurvePublicKey]:
            if key_params['identifier'] != cls.CURVE_IDENTIFIER:
                raise ValueError(
                    'The curve identifier encoded in the public key does not '
                    'correspond to the key type'
                )
            return ec.EllipticCurvePublicKey.from_encoded_point(
                ec.get_curve_for_oid(ObjectIdentifier(cls.CURVE_OID))(),
                key_params['q']
            )

        return {
            ec.EllipticCurvePublicKey: ConversionFunctions(
                ecdsa_public_key_convert_from_cryptography,
                ecdsa_public_key_convert_to_cryptography
            )
        }

    def check_params_are_valid(self) -> None:
        """Checks whether the values within this parameters object conform to
        the format instructions, whether the curve identifier encoded in the
        public key corresponds to the key type, and whether the point lies on
        the elliptic curve indicated by the identifier.

        Raises:
            UserWarning: A parameter value is missing or does not have a type
                that matches the format instructions for this key type, the
                curve identifier encoded in the public key corresponds to the
                key type, or the point does not lie on the elliptic curve
                indicated by the identifier.
        """
        super().check_params_are_valid()
        if 'identifier' not in self:
            return
        if self.CURVE_IDENTIFIER != self['identifier']:
            warnings.warn(UserWarning(
                'The curve identifier encoded in the public key does not '
                'correspond to the key type'
            ))
        if 'q' not in self or type(self['q']) != bytes:
            return
        try:
            # Discard result
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.get_curve_for_oid(ObjectIdentifier(self.CURVE_OID))(),
                self['q']
            )
        except ValueError:
            warnings.warn(UserWarning(  # pylint: disable=raise-missing-from
                'The point does not lie on the elliptic curve indicated by '
                'the identifier'
            ))


ECDSAPrivateKeyParamsTypeVar = typing.TypeVar(
    'ECDSAPrivateKeyParamsTypeVar',
    bound='ECDSAPrivateKeyParams'
)


class ECDSAPrivateKeyParams(PrivateKeyParams, ECDSAPublicKeyParams):
    """The parameters comprising a private key in the Elliptic Curve Digital Signature
    Algorithm cryptosystem.

    The names and iteration order of parameters of a *private* ECDSA key are:

    * ``identifier``: The identifier of the elliptic curve domain parameters,
                      as specified in
                      `RFC 5656 <https://www.ietf.org/rfc/rfc5656.html#section-6.1>`_
                      (:any:`str`).
    * ``q``: The public key, the elliptic curve point encoded as described in
             `SEC 1 <https://www.secg.org/sec1-v2.pdf>`_ (:any:`bytes`).
    * ``d``: The private key (:any:`int`).

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
        'identifier': PascalStyleFormatInstruction.STRING,
        'q': PascalStyleFormatInstruction.BYTES,
        'd': PascalStyleFormatInstruction.MPINT,
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType(
            ECDSAPrivateKeyParams.__FORMAT_INSTRUCTIONS_DICT
        )

    @classmethod
    def generate_private_params(
        cls: typing.Type[ECDSAPrivateKeyParamsTypeVar],
        **kwargs: typing.Any
    ) -> typing.Union[
        ECDSAPrivateKeyParamsTypeVar,
        'ECDSA_NISTP256_PrivateKeyParams'
    ]:
        """Constructs and initializes a ECDSA private key parameters object
        with generated values. If called on the ``ECDSAPrivateKeyParams``
        class, delegates to ``ECDSA_NISTP256_PrivateKeyParams``.

        Args:
            kwargs
                Keyword arguments consumed to generate parameter values.

        Returns:
            A private key parameters object with generated values valid for
            a ECDSA private key.
        """

        if cls == ECDSAPrivateKeyParams:
            return ECDSA_NISTP256_PrivateKeyParams.generate_private_params(
                **kwargs
            )

        private_key = ec.generate_private_key(
            curve=ec.get_curve_for_oid(ObjectIdentifier(cls.CURVE_OID))()
        )
        return cls({
            'identifier': cls.CURVE_IDENTIFIER,
            'q': private_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'd': private_key.private_numbers().private_value,
        })

    @classmethod
    def conversion_functions(
        cls
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Conversion functions for key objects of the following types:

        * :any:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`

        Returns:
            A :py:class:`typing.Mapping` from the above types of key objects
            to functions that take key objects of these types and return
            parameter values.
        """
        def ecdsa_private_key_convert_from_cryptography(
            key_object: ec.EllipticCurvePrivateKey
        ) -> typing.Optional[ValuesDict]:
            if key_object.curve.name != cls.CURVE_NAME:
                return None
            private_numbers = key_object.private_numbers()
            public_bytes = key_object.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
            return {
                'identifier': cls.CURVE_IDENTIFIER,
                'q': public_bytes,
                'd': private_numbers.private_value,
            }

        def ecdsa_private_key_convert_to_cryptography(
            key_params: ValuesDict
        ) -> ec.EllipticCurvePrivateKey:
            return ec.EllipticCurvePrivateNumbers(
                key_params['d'],
                ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.get_curve_for_oid(ObjectIdentifier(cls.CURVE_OID))(),
                    key_params['q']
                ).public_numbers()
            ).private_key()

        return {
            ec.EllipticCurvePrivateKey: ConversionFunctions(
                ecdsa_private_key_convert_from_cryptography,
                ecdsa_private_key_convert_to_cryptography
            )
        }


class ECDSA_NISTP256_PublicKeyParams(ECDSAPublicKeyParams):
    """
    The parameters representing a public ECDSA key on the ``nistp256`` curve.
    """

    @staticmethod
    def get_curve_identifier() -> str:
        """The value ``'nistp256'``.
        """
        return 'nistp256'

    @staticmethod
    def get_curve_name() -> str:
        """The value ``'secp256r1'``.
        """
        return 'secp256r1'

    @staticmethod
    def get_curve_oid() -> str:
        """The value ``'1.2.840.10045.3.1.7'``.
        """
        return '1.2.840.10045.3.1.7'


class ECDSA_NISTP256_PrivateKeyParams(ECDSA_NISTP256_PublicKeyParams, ECDSAPrivateKeyParams):
    """
    The parameters representing a private ECDSA key on the ``nistp256`` curve.
    """


class ECDSA_NISTP384_PublicKeyParams(ECDSAPublicKeyParams):
    """
    The parameters representing a public ECDSA key on the ``nistp384`` curve.
    """

    @staticmethod
    def get_curve_identifier() -> str:
        """The value ``'nistp384'``.
        """
        return 'nistp384'

    @staticmethod
    def get_curve_name() -> str:
        """The value ``'secp384r1'``.
        """
        return 'secp384r1'

    @staticmethod
    def get_curve_oid() -> str:
        """The value ``'1.3.132.0.34'``.
        """
        return '1.3.132.0.34'


class ECDSA_NISTP384_PrivateKeyParams(ECDSA_NISTP384_PublicKeyParams, ECDSAPrivateKeyParams):
    """
    The parameters representing a private ECDSA key on the ``nistp384`` curve.
    """


class ECDSA_NISTP521_PublicKeyParams(ECDSAPublicKeyParams):
    """
    The parameters representing a public ECDSA key on the ``nistp521`` curve.
    """

    @staticmethod
    def get_curve_identifier() -> str:
        """The value ``'nistp521'``.
        """
        return 'nistp521'

    @staticmethod
    def get_curve_name() -> str:
        """The value ``'secp521r1'``.
        """
        return 'secp521r1'

    @staticmethod
    def get_curve_oid() -> str:
        """The value ``'1.3.132.0.35'``.
        """
        return '1.3.132.0.35'


class ECDSA_NISTP521_PrivateKeyParams(ECDSA_NISTP521_PublicKeyParams, ECDSAPrivateKeyParams):
    """
    The parameters representing a private ECDSA key on the ``nistp521`` curve.
    """
