import collections
import abc
import warnings
import enum
from collections import namedtuple

from openssh_key.pascal_style_byte_stream import (
    PascalStyleByteStream,
    PascalStyleFormatInstruction
)


class PublicKeyParams(collections.UserDict, abc.ABC):
    def __init__(self, params: dict, comment: str):
        self.data = params
        self._comment = comment
        self.check_params_are_valid()

    @staticmethod
    @abc.abstractmethod
    def public_format_instructions_dict():
        return {}

    @property
    def comment(self):
        return self._comment

    @property
    def params(self):
        return self.data

    @staticmethod
    def check_params_match_format_instructions_dict(
        params_dict,
        format_instructions_dict
    ):
        for k, v in format_instructions_dict.items():
            if k not in params_dict:
                warnings.warn(k + ' missing')
            elif type(params_dict[k]) != v.value:
                warnings.warn(
                    k + ' should be of class ' + str(v.value.__name__)
                )

    def check_params_are_valid(self):
        self.check_params_match_format_instructions_dict(
            self.data, self.public_format_instructions_dict())

    def __str__(self):
        return str({
            'comment': self._comment,
            'params': self.data
        })


class PrivateKeyParams(PublicKeyParams):
    @staticmethod
    @abc.abstractmethod
    def private_format_instructions_dict():
        return {}

    def check_params_are_valid(self):
        self.check_params_match_format_instructions_dict(
            self.data, self.private_format_instructions_dict()
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


PublicPrivateKeyParamsClasses = namedtuple(
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


def create_key_params(key_type, public_or_private):
    public_private_key_params_classes = _KEY_TYPE_MAPPING[key_type]
    if public_or_private == 'public':
        return public_private_key_params_classes.PublicKeyParamsClass
    elif public_or_private == 'private':
        return public_private_key_params_classes.PrivateKeyParamsClass
    else:
        raise NotImplementedError()
