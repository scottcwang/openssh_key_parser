"""Classes representing public- and private-key parameters for keys of various
cryptosystems.
"""

import collections
import abc
import warnings
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ed25519
)

from openssh_key.pascal_style_byte_stream import (
    PascalStyleByteStream,
    PascalStyleFormatInstruction,
    FormatInstructionsDict,
    ValuesDict
)


PublicKeyParamsTypeVar = typing.TypeVar(
    'PublicKeyParamsTypeVar',
    bound='PublicKeyParams'
)


class ConversionFunctions(typing.NamedTuple):
    """Functions to convert :any:`typing.Mapping`, representing parameter
    values, to an object of a certain type, and *vice versa*.
    """
    object_to_mapping: typing.Callable[
        [typing.Any],
        ValuesDict
    ]
    """Functions to convert an object of a certain type to a
    :any:`typing.Mapping` representing the parameter values in the object.
    """

    mapping_to_object: typing.Callable[
        [ValuesDict],
        typing.Any
    ]
    """Functions to convert a :any:`typing.Mapping` containing parameter
    values to an object of a certain type.
    """


# https://github.com/python/mypy/issues/5264
if typing.TYPE_CHECKING:  # pragma: no cover
    BaseDict = collections.UserDict[  # pylint: disable=unsubscriptable-object
        str, typing.Any
    ]
else:
    BaseDict = collections.UserDict


class PublicKeyParams(BaseDict, abc.ABC):
    """The parameters comprising a key.

    The names and iteration order of parameters of *public* keys recognized by
    implementations of the Secure Shell (SSH) protocol are as specified in
    `RFC 4253 <https://tools.ietf.org/html/rfc4253#section-6.6>`_.

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A value in ``params`` is missing or does not have a type
            that matches the format instructions for this key type.
    """

    def __init__(self, params: ValuesDict):
        super().__init__(params)
        self.check_params_are_valid()

    @classmethod
    def convert_from(
        cls,
        key_object: typing.Any
    ) -> 'PublicKeyParams':
        """Constructs and initializes a parameters object for this key type
        from attributes contained in the given object.

        This classmethod searches :any:`conversion_functions` for a class that
        is a superclass of ``key_object``. If one is found, it returns the
        parameters object from the :any:`typing.Mapping` returned by the
        corresponding :any:`object_to_mapping` function. Otherwise, it searches
        its subclasses' :any:`conversion_functions`, traversing pre-order.

        Args:
            key_object
                An object containing key parameter values.

        Raises:
            NotImplementedError: ``key_object`` is not of a supported type,
                or it does not contain the attributes necessary to construct
                a parameters object of this class.
        """
        params_dict: typing.Optional[ValuesDict] = None
        for k, v in cls.conversion_functions().items():
            if isinstance(key_object, k):
                params_dict = v.object_to_mapping(key_object)
                break
        if params_dict is None:
            for subcls in cls.__subclasses__():
                try:
                    params_dict = dict(subcls.convert_from(key_object))
                except NotImplementedError:
                    pass
                if params_dict is not None:
                    break
        if params_dict is not None:
            return cls({
                k: params_dict[k]
                for k in cls.FORMAT_INSTRUCTIONS_DICT
            })
        raise NotImplementedError()

    @staticmethod
    def conversion_functions(
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Functions to extract parameter values dicts for supported types of
        key objects.

        Returns:
            A :py:class:`typing.Mapping` from types of key objects to functions
            that take key objects of that type and return parameter values.
        """
        return {}

    FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[FormatInstructionsDict]
    """The Pascal-style byte stream format instructions for the parameters
    of a key of this type.
    """

    @property
    def params(self) -> ValuesDict:
        """The values within this parameters object.

        Returns:
            The parameter values.
        """
        return self.data

    def check_params_are_valid(self) -> None:
        """Checks whether the values within this parameters object conform to
        the format instructions.

        Raises:
            UserWarning: A parameter value is missing or does not have a type
                that matches the format instructions for this key type.
        """
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.data,
            self.FORMAT_INSTRUCTIONS_DICT
        )

    def convert_to(  # pylint: disable=no-self-use
        self,
        destination_class: typing.Type[typing.Any]
    ) -> typing.Any:
        """Creates and initializes an object of the given type containing the
        values of this parameters object.

        This method searches :any:`conversion_functions` for a class that
        is a subclass of ``key_object``. If one is found, it passes this
        parameters object to the corresponding :any:`mapping_to_object`.
        Otherwise, it searches its superclasses' :any:`conversion_functions`
        in the same way, in method resolution order, up to and including
        :any:`PublicKeyParams`.

        Args:
            destination_class
                The type of the object to which the values of this parameters
                object are to be converted.

        Raises:
            ValueError: ``destination_class`` is not a class.
            ImportError: ``destination_class`` cannot be imported.
            NotImplementedError: Converting this parameters object to an
                object of type ``destination_class`` is not supported.
        """
        if not isinstance(destination_class, type):
            raise ValueError('destination_class must be a class')
        for supercls in self.__class__.__mro__:
            if not issubclass(supercls, PublicKeyParams):
                break
            for candidate_class in supercls.conversion_functions():
                if issubclass(candidate_class, destination_class):
                    return supercls.conversion_functions()[
                        candidate_class
                    ].mapping_to_object(self)
        raise NotImplementedError()


PrivateKeyParamsTypeVar = typing.TypeVar(
    'PrivateKeyParamsTypeVar',
    bound='PrivateKeyParams'
)


class PrivateKeyParams(PublicKeyParams):
    """The parameters comprising a private key, a superset of those parameters
    comprising a public key (:any:`PublicKeyParams`).

    The names and iteration order of parameters of *private* keys recognized by
    implementations of the Secure Shell (SSH) protocol are as specified for
    the ``SSH_AGENTC_ADD_IDENTITY`` message of the
    `ssh-agent protocol <https://tools.ietf.org/html/draft-miller-ssh-agent-03#section-4.2>`_.
    """

    @classmethod
    @abc.abstractmethod
    def generate_private_params(
        cls: typing.Type[PrivateKeyParamsTypeVar],
        **kwargs: typing.Any
    ) -> PrivateKeyParamsTypeVar:
        """Constructs and initializes a parameters object with generated
        values.

        Args:
            kwargs
                Keyword arguments consumed to generate parameter values.

        Returns:
            A private key parameters object with generated values valid for
            a private key of this type.
        """
        return cls({})


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
    FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[FormatInstructionsDict] = {
        'e': PascalStyleFormatInstruction.MPINT,
        'n': PascalStyleFormatInstruction.MPINT,
    }

    @staticmethod
    def conversion_functions(
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
            key_object: rsa.RSAPublicKey
        ) -> ValuesDict:
            public_numbers = key_object.public_numbers()
            return {
                'e': public_numbers.e,
                'n': public_numbers.n
            }

        def rsa_public_key_convert_to_cryptography(
            key_params: ValuesDict
        ) -> rsa.RSAPublicKey:
            return rsa.RSAPublicNumbers(
                key_params['e'],
                key_params['n']
            ).public_key(default_backend())

        return {
            rsa.RSAPublicKey: ConversionFunctions(
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
    FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[FormatInstructionsDict] = {
        'n': PascalStyleFormatInstruction.MPINT,
        'e': PascalStyleFormatInstruction.MPINT,
        'd': PascalStyleFormatInstruction.MPINT,
        'iqmp': PascalStyleFormatInstruction.MPINT,
        'p': PascalStyleFormatInstruction.MPINT,
        'q': PascalStyleFormatInstruction.MPINT
    }

    PUBLIC_EXPONENT = 65537
    KEY_SIZE = 4096

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
        private_key = rsa.generate_private_key(
            public_exponent=(
                kwargs['e'] if 'e' in kwargs else cls.PUBLIC_EXPONENT
            ),
            key_size=(
                kwargs['key_size'] if 'key_size' in kwargs else cls.KEY_SIZE
            ),
            backend=default_backend()
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

    @staticmethod
    def conversion_functions(
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Conversion functions for key objects of the following types:

        * :any:`cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKeyWithSerialization`

        Returns:
            A :py:class:`typing.Mapping` from the above types of key objects
            to functions that take key objects of these types and return
            parameter values.
        """
        def rsa_private_key_convert_from_cryptography(
            key_object: rsa.RSAPrivateKeyWithSerialization
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
        ) -> rsa.RSAPrivateKeyWithSerialization:
            key_object = rsa.RSAPrivateNumbers(
                key_params['p'],
                key_params['q'],
                key_params['d'],
                rsa.rsa_crt_dmp1(
                    key_params['d'], key_params['p']),
                rsa.rsa_crt_dmp1(
                    key_params['d'], key_params['q']),
                key_params['iqmp'],
                rsa.RSAPublicNumbers(
                    key_params['e'],
                    key_params['n']
                )
            ).private_key(default_backend())
            return typing.cast(rsa.RSAPrivateKeyWithSerialization, key_object)

        return {
            rsa.RSAPrivateKeyWithSerialization: ConversionFunctions(
                rsa_private_key_convert_from_cryptography,
                rsa_private_key_convert_to_cryptography
            )
        }


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
    FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[ FormatInstructionsDict] = {
        'public': PascalStyleFormatInstruction.BYTES
    }

    KEY_SIZE = 32

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
        if 'public' in self.data \
                and len(self.data['public']) != self.KEY_SIZE:
            warnings.warn('Public key not of length ' + str(self.KEY_SIZE))

    @staticmethod
    def conversion_functions(
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
            key_object: ed25519.Ed25519PublicKey
        ) -> ValuesDict:
            return {
                'public': key_object.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            }

        def ed25519_public_key_convert_to_cryptography(
            key_params: ValuesDict
        ) -> ed25519.Ed25519PublicKey:
            return ed25519.Ed25519PublicKey.from_public_bytes(
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
            ed25519.Ed25519PublicKey: ConversionFunctions(
                ed25519_public_key_convert_from_cryptography,
                ed25519_public_key_convert_to_cryptography
            ),
            bytes: ConversionFunctions(
                ed25519_public_key_convert_from_bytes,
                ed25519_public_key_convert_to_bytes
            )
        }

        try:
            import nacl

            def ed25519_public_key_convert_from_pynacl(
                key_object: nacl.signing.VerifyKey
            ) -> ValuesDict:
                return {
                    'public': bytes(key_object)
                }

            def ed25519_public_key_convert_to_pynacl(
                key_params: ValuesDict
            ) -> nacl.signing.VerifyKey:
                return nacl.signing.VerifyKey(key_params['public'])

            conversion_functions_dict[
                nacl.signing.VerifyKey
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

    FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[ FormatInstructionsDict] = {
        'public': PascalStyleFormatInstruction.BYTES,
        'private_public': PascalStyleFormatInstruction.BYTES
    }

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
        if 'private_public' not in self.data:
            return
        if self.data['private_public'][self.KEY_SIZE:] \
                != self.data['public']:
            warnings.warn('Public key does not match')
        if len(self.data['private_public'][self.KEY_SIZE:]) != self.KEY_SIZE:
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

        private_key = ed25519.Ed25519PrivateKey.generate()

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

    @staticmethod
    def conversion_functions(
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
            key_object: ed25519.Ed25519PrivateKey
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
        ) -> ed25519.Ed25519PrivateKey:
            return ed25519.Ed25519PrivateKey.from_private_bytes(
                key_params[
                    'private_public'
                ][:Ed25519PrivateKeyParams.KEY_SIZE]
            )

        def ed25519_private_key_convert_from_bytes(
            key_object: bytes
        ) -> ValuesDict:
            private_bytes = key_object
            public_bytes = ed25519.Ed25519PrivateKey.from_private_bytes(
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
            ed25519.Ed25519PrivateKey: ConversionFunctions(
                ed25519_private_key_convert_from_cryptography,
                ed25519_private_key_convert_to_cryptography
            ),
            bytes: ConversionFunctions(
                ed25519_private_key_convert_from_bytes,
                ed25519_private_key_convert_to_bytes
            )
        }

        try:
            import nacl

            def ed25519_private_key_convert_from_pynacl(
                key_object: nacl.signing.SigningKey
            ) -> ValuesDict:
                private_bytes = bytes(key_object)
                public_bytes = bytes(key_object.verify_key)
                return {
                    'public': public_bytes,
                    'private_public': private_bytes + public_bytes
                }

            def ed25519_private_key_convert_to_pynacl(
                key_params: ValuesDict
            ) -> nacl.signing.SigningKey:
                return nacl.signing.SigningKey(
                    key_params[
                        'private_public'
                    ][:Ed25519PrivateKeyParams.KEY_SIZE]
                )

            conversion_functions_dict[
                nacl.signing.SigningKey
            ] = ConversionFunctions(
                ed25519_private_key_convert_from_pynacl,
                ed25519_private_key_convert_to_pynacl
            )
        except ImportError:
            pass

        return conversion_functions_dict


class PublicPrivateKeyParamsClasses(typing.NamedTuple):
    publicKeyParamsClass: typing.Type[PublicKeyParams]
    privateKeyParamsClass: typing.Type[PrivateKeyParams]


_KEY_TYPE_MAPPING = {
    'ssh-rsa': PublicPrivateKeyParamsClasses(
        RSAPublicKeyParams, RSAPrivateKeyParams
    ),
    'ssh-ed25519': PublicPrivateKeyParamsClasses(
        Ed25519PublicKeyParams, Ed25519PrivateKeyParams
    ),
}


def create_public_key_params(key_type: str) -> typing.Type[PublicKeyParams]:
    """Returns the class corresponding to public key parameters objects of the
    given key type name.

    Args:
        key_type
            The name of the OpenSSH key type.

    Returns:
        The subclass of :any:`PublicKeyParams` corresponding to the key type
        name.

    Raises:
        KeyError: There is no subclass of :any:`PublicKeyParams` corresponding
            to the given key type name.
    """
    return _KEY_TYPE_MAPPING[key_type].publicKeyParamsClass


def create_private_key_params(key_type: str) -> typing.Type[PrivateKeyParams]:
    """Returns the class corresponding to private key parameters objects of the
    given key type name.

    Args:
        key_type
            The name of the OpenSSH key type.

    Returns:
        The subclass of :any:`PrivateKeyParams` corresponding to the key type
        name.

    Raises:
        KeyError: There is no subclass of :any:`PrivateKeyParams` corresponding
            to the given key type name.
    """
    return _KEY_TYPE_MAPPING[key_type].privateKeyParamsClass
