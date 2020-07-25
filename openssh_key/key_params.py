import collections
import abc
import warnings
import enum

from openssh_key.pascal_style_byte_stream import (
    PascalStyleByteStream,
    PascalStyleFormatInstruction
)


class PublicKeyParams(collections.UserDict, abc.ABC):
    def __init__(self, params: dict):
        self.data = params
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


class RSAPublicKeyParams(PublicKeyParams):
    @staticmethod
    def public_format_instructions_dict():
        return {
            'e': PascalStyleFormatInstruction.MPINT,
            'n': PascalStyleFormatInstruction.MPINT,
        }


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


ED25519_KEY_SIZE = 32


class Ed25519PublicKeyParams(PublicKeyParams):
    @staticmethod
    def public_format_instructions_dict():
        return {
            'public': PascalStyleFormatInstruction.BYTES
        }

    def check_params_are_valid(self):
        super().check_params_are_valid()
        if 'public' in self.data \
                and len(self.data['public']) != ED25519_KEY_SIZE:
            warnings.warn('Public key not of length ' + str(ED25519_KEY_SIZE))


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
        if self.data['private_public'][ED25519_KEY_SIZE:] \
                != self.data['public']:
            warnings.warn('Public key does not match')
        if len(self.data['private_public'][ED25519_KEY_SIZE:]) \
                != ED25519_KEY_SIZE:
            warnings.warn(
                'Private key not of length ' + str(ED25519_KEY_SIZE)
            )


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
