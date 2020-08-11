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
    object_to_mapping: typing.Callable[
        [typing.Any],
        typing.Mapping[str, typing.Any]
    ]
    mapping_to_object: typing.Callable[
        [typing.Mapping[str, typing.Any]],
        typing.Any
    ]


# https://github.com/python/mypy/issues/5264
if typing.TYPE_CHECKING:
    BaseDict = collections.UserDict[  # pylint: disable=unsubscriptable-object
        str, typing.Any
    ]
else:
    BaseDict = collections.UserDict


class PublicKeyParams(BaseDict, abc.ABC):
    def __init__(self, params: typing.Mapping[str, typing.Any]):
        super().__init__(params)
        self.check_params_are_valid()

    @classmethod
    def convert_from(
        cls,
        key_object: typing.Any
    ) -> 'PublicKeyParams':
        params_dict: typing.Optional[typing.Mapping[str, typing.Any]] = None
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
                for k in cls.format_instructions_dict()
            })
        raise NotImplementedError()

    @staticmethod
    def conversion_functions(
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        return {}

    @staticmethod
    @abc.abstractmethod
    def format_instructions_dict() -> FormatInstructionsDict:
        return {}

    @property
    def params(self) -> ValuesDict:
        return self.data

    def check_params_are_valid(self) -> None:
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.data,
            self.format_instructions_dict()
        )

    def convert_to(  # pylint: disable=no-self-use
        self,
        destination_class: typing.Type[typing.Any]
    ) -> typing.Any:
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
    @classmethod
    @abc.abstractmethod
    def generate_private_params(
        cls: typing.Type[PrivateKeyParamsTypeVar],
        **kwargs: typing.Any
    ) -> PrivateKeyParamsTypeVar:
        return cls({})


class RSAPublicKeyParams(PublicKeyParams):
    @staticmethod
    def format_instructions_dict() -> FormatInstructionsDict:
        return {
            'e': PascalStyleFormatInstruction.MPINT,
            'n': PascalStyleFormatInstruction.MPINT,
        }

    @staticmethod
    def conversion_functions(
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        def rsa_public_key_convert_from_cryptography(
            key_object: rsa.RSAPublicKey
        ) -> typing.Mapping[str, typing.Any]:
            public_numbers = key_object.public_numbers()
            return {
                'e': public_numbers.e,
                'n': public_numbers.n
            }

        def rsa_public_key_convert_to_cryptography(
            key_params: typing.Mapping[str, typing.Any]
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
    @staticmethod
    def format_instructions_dict() -> FormatInstructionsDict:
        return {
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
        def rsa_private_key_convert_from_cryptography(
            key_object: rsa.RSAPrivateKeyWithSerialization
        ) -> typing.Mapping[str, typing.Any]:
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
            key_params: typing.Mapping[str, typing.Any]
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
    @staticmethod
    def format_instructions_dict() -> FormatInstructionsDict:
        return {
            'public': PascalStyleFormatInstruction.BYTES
        }

    KEY_SIZE = 32

    def check_params_are_valid(self) -> None:
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
        def ed25519_public_key_convert_from_cryptography(
            key_object: ed25519.Ed25519PublicKey
        ) -> typing.Mapping[str, typing.Any]:
            return {
                'public': key_object.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            }

        def ed25519_public_key_convert_to_cryptography(
            key_params: typing.Mapping[str, typing.Any]
        ) -> ed25519.Ed25519PublicKey:
            return ed25519.Ed25519PublicKey.from_public_bytes(
                key_params['public']
            )

        def ed25519_public_key_convert_from_bytes(
            key_object: bytes
        ) -> typing.Mapping[str, typing.Any]:
            return {
                'public': key_object
            }

        def ed25519_public_key_convert_to_bytes(
            key_params: typing.Mapping[str, typing.Any]
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
            ) -> typing.Mapping[str, typing.Any]:
                return {
                    'public': bytes(key_object)
                }

            def ed25519_public_key_convert_to_pynacl(
                key_params: typing.Mapping[str, typing.Any]
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
    @staticmethod
    def format_instructions_dict() -> FormatInstructionsDict:
        return {
            'public': PascalStyleFormatInstruction.BYTES,
            'private_public': PascalStyleFormatInstruction.BYTES
        }

    def check_params_are_valid(self) -> None:
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
        def ed25519_private_key_convert_from_cryptography(
            key_object: ed25519.Ed25519PrivateKey
        ) -> typing.Mapping[str, typing.Any]:
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
            key_params: typing.Mapping[str, typing.Any]
        ) -> ed25519.Ed25519PrivateKey:
            return ed25519.Ed25519PrivateKey.from_private_bytes(
                key_params[
                    'private_public'
                ][:Ed25519PrivateKeyParams.KEY_SIZE]
            )

        def ed25519_private_key_convert_from_bytes(
            key_object: bytes
        ) -> typing.Mapping[str, typing.Any]:
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
            key_params: typing.Mapping[str, typing.Any]
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
            ) -> typing.Mapping[str, typing.Any]:
                private_bytes = bytes(key_object)
                public_bytes = bytes(key_object.verify_key)
                return {
                    'public': public_bytes,
                    'private_public': private_bytes + public_bytes
                }

            def ed25519_private_key_convert_to_pynacl(
                key_params: typing.Mapping[str, typing.Any]
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
    return _KEY_TYPE_MAPPING[key_type].publicKeyParamsClass


def create_private_key_params(key_type: str) -> typing.Type[PrivateKeyParams]:
    return _KEY_TYPE_MAPPING[key_type].privateKeyParamsClass
