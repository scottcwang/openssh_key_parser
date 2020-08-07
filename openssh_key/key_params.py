import collections
import abc
import warnings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ed25519
)

from openssh_key.pascal_style_byte_stream import (
    PascalStyleByteStream,
    PascalStyleFormatInstruction
)


class PublicKeyParams(collections.UserDict, abc.ABC):
    def __init__(self, params: dict):
        super().__init__(params)
        self.check_params_are_valid()

    @staticmethod
    @abc.abstractmethod
    def public_format_instructions_dict():
        return {}

    @property
    def params(self):
        return self.data

    def check_params_are_valid(self):
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.data,
            self.public_format_instructions_dict()
        )

    def convert_to(self, destination_class):  # pylint: disable=no-self-use
        if not isinstance(destination_class, type):
            raise ValueError('destination_class must be a class')
        raise NotImplementedError()


class PrivateKeyParams(PublicKeyParams):
    @staticmethod
    @abc.abstractmethod
    def private_format_instructions_dict():
        return {}

    def check_params_are_valid(self):
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.data,
            self.private_format_instructions_dict()
        )

    @classmethod
    @abc.abstractmethod
    def generate_private_params(cls, **kwargs):
        return cls({})


class RSAPublicKeyParams(PublicKeyParams):
    @staticmethod
    def public_format_instructions_dict():
        return {
            'e': PascalStyleFormatInstruction.MPINT,
            'n': PascalStyleFormatInstruction.MPINT,
        }

    def convert_to(self, destination_class):
        if destination_class == rsa.RSAPublicKey:
            return rsa.RSAPublicNumbers(
                self['e'], self['n']
            ).public_key(default_backend())
        return super().convert_to(destination_class)


class RSAPrivateKeyParams(PrivateKeyParams, RSAPublicKeyParams):
    @staticmethod
    def private_format_instructions_dict():
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
    def generate_private_params(cls, **kwargs):
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

    def convert_to(self, destination_class):
        if destination_class == rsa.RSAPrivateKey:
            return rsa.RSAPrivateNumbers(
                self['p'],
                self['q'],
                self['d'],
                rsa.rsa_crt_dmp1(
                    self['d'], self['p']),
                rsa.rsa_crt_dmp1(
                    self['d'], self['q']),
                self['iqmp'],
                rsa.RSAPublicNumbers(
                    self['e'],
                    self['n']
                )
            ).private_key(default_backend())
        return super().convert_to(destination_class)


class Ed25519PublicKeyParams(PublicKeyParams):
    @staticmethod
    def public_format_instructions_dict():
        return {
            'public': PascalStyleFormatInstruction.BYTES
        }

    KEY_SIZE = 32

    def check_params_are_valid(self):
        super().check_params_are_valid()
        if 'public' in self.data \
                and len(self.data['public']) != self.KEY_SIZE:
            warnings.warn('Public key not of length ' + str(self.KEY_SIZE))

    def convert_to(self, destination_class):
        if destination_class == ed25519.Ed25519PublicKey:
            return ed25519.Ed25519PublicKey.from_public_bytes(self['public'])
        if destination_class == bytes:
            return self['public']
        try:
            import nacl
            if destination_class == nacl.public.PublicKey:
                return nacl.public.PublicKey(self['public'])
        except ImportError:
            pass
        return super().convert_to(destination_class)


class Ed25519PrivateKeyParams(PrivateKeyParams, Ed25519PublicKeyParams):
    @staticmethod
    def private_format_instructions_dict():
        return {
            'public': PascalStyleFormatInstruction.BYTES,
            'private_public': PascalStyleFormatInstruction.BYTES
        }

    def check_params_are_valid(self):
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
    def generate_private_params(cls, **kwargs):
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

    def convert_to(self, destination_class):
        if destination_class == ed25519.Ed25519PrivateKey:
            return ed25519.Ed25519PrivateKey.from_private_bytes(
                self['private_public'][:self.KEY_SIZE]
            )
        if destination_class == bytes:
            return self['private_public'][:self.KEY_SIZE]
        try:
            import nacl
            if destination_class == nacl.public.PrivateKey:
                return nacl.public.PrivateKey(
                    self['private_public'][:self.KEY_SIZE]
                )
        except ImportError:
            pass
        return super().convert_to(destination_class)


PublicPrivateKeyParamsClasses = collections.namedtuple(
    'PublicPrivateKeyParamsClasses', [
        'PublicKeyParamsClass', 'PrivateKeyParamsClass'
    ]
)


_KEY_TYPE_MAPPING = {
    'ssh-rsa': PublicPrivateKeyParamsClasses(
        RSAPublicKeyParams, RSAPrivateKeyParams
    ),
    'ssh-ed25519': PublicPrivateKeyParamsClasses(
        Ed25519PublicKeyParams, Ed25519PrivateKeyParams
    ),
}


def create_public_key_params(key_type):
    return _KEY_TYPE_MAPPING[key_type].PublicKeyParamsClass


def create_private_key_params(key_type):
    return _KEY_TYPE_MAPPING[key_type].PrivateKeyParamsClass
