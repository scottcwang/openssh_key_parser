import collections
import abc
import warnings
import enum
from collections import namedtuple

from openssh_key.pascal_style_byte_stream import PascalStyleByteStream, PascalStyleFormatInstruction


class PublicKeyParams(collections.UserDict, abc.ABC):  # pragma: no cover
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
    def check_params_match_format_instructions_dict(params_dict, format_instructions_dict):
        for k, v in format_instructions_dict.items():
            if k not in params_dict:
                warnings.warn(k + ' missing')
            elif type(params_dict[k]) != v.value:
                warnings.warn(k + ' should be a(n) ' + str(v.value))

    def check_params_are_valid(self):
        self.check_params_match_format_instructions_dict(
            self.data, self.public_format_instructions_dict())

    def __str__(self):
        return str({
            'comment': self._comment,
            'params': self.data
        })


class PrivateKeyParams(PublicKeyParams):  # pragma: no cover
    @staticmethod
    @abc.abstractmethod
    def private_format_instructions_dict():
        return {}

    def check_params_are_valid(self):
        self.check_params_match_format_instructions_dict(
            self.data, self.private_format_instructions_dict())


class RSAPublicKeyParams(PublicKeyParams):
    @staticmethod
    def public_format_instructions_dict():
        return {
            'e': PascalStyleFormatInstruction.MPINT,
            'n': PascalStyleFormatInstruction.MPINT,
        }

    def check_params_are_valid(self):
        return super().check_params_are_valid()  # TODO


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

    def check_params_are_valid(self):
        return super().check_params_are_valid()  # TODO


class Ed25519PublicKeyParams(PublicKeyParams):
    @staticmethod
    def public_format_instructions_dict():
        return {
            'public': PascalStyleFormatInstruction.BYTES
        }

    def check_params_are_valid(self):
        return super().check_params_are_valid()  # TODO


class Ed25519PrivateKeyParams(PrivateKeyParams, Ed25519PublicKeyParams):
    @staticmethod
    def private_format_instructions_dict():
        return {
            'public': PascalStyleFormatInstruction.BYTES,
            'private_public': PascalStyleFormatInstruction.BYTES
        }

    def check_params_are_valid(self):
        return super().check_params_are_valid()  # TODO


PublicPrivateKeyParamsClasses = namedtuple(
    'PublicPrivateKeyParamsClasses', [
        'PublicKeyParamsClass', 'PrivateKeyParamsClass'
    ])


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
