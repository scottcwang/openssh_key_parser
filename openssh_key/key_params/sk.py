"""
Classes representing keys stored on security keys.
"""

import abc
import enum
import types
import typing

from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleFormatInstruction)

from .common import PrivateKeyParams, PublicKeyParams
from .ecdsa import ECDSA_NISTP256_PublicKeyParams
from .ed25519 import Ed25519PublicKeyParams


class SecurityKeyFlag(enum.Enum):
    """
    Security key flags supported by OpenSSH.
    """

    USER_PRESENCE_REQUIRED = 0x1
    """
    Whether the private key requires the user to touch it before
    generating a signature (equivalent to executing ``ssh-keygen``
    *without* ``-O no-touch-required``).
    """

    USER_VERIFCATION_REQUIRED = 0x4
    """
    Whether the private key requires user verification (equivalent to
    executing ``ssh-keygen`` with ``-O verify-required``). Not all FIDO
    authenticators support this option. OpenSSH presently supports only
    PIN verification.
    """

    RESIDENT_KEY = 0x20
    """
    Whether the private key should be stored on the FIDO authenticator
    (equivalent to executing ``ssh-keygen`` with ``-O resident``).
    """


class SecurityKeyPublicKeyParams(
    PublicKeyParams,
    abc.ABC
):
    """
    The parameters comprising a public key corresponding to a private key
    that is stored in a U2F/FIDO security key. OpenSSH supports security keys
    presenting the following key types:

    * :py:class:`.ecdsa.ECDSA_NISTP256_PublicKeyParams`
    * :py:class:`.ed25519.Ed25519PublicKeyParams`

    The names and iteration order of parameters of a *public* security key is:

    * The parameters of the public key.
    * ``application``: User-specified, typically ``ssh:`` (:any:`str`).

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A parameter value from the above list is missing from
            ``params`` or does not have the correct type.
    """
    @staticmethod
    @abc.abstractmethod
    def get_sk_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return PublicKeyParams

    __FORMAT_INSTRUCTIONS_DICT_SUFFIX: typing.ClassVar[FormatInstructionsDict] = {
        'application': PascalStyleFormatInstruction.STRING,
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType({
            **cls.get_sk_base_public_key_class().get_format_instructions_dict(),
            **SecurityKeyPublicKeyParams.__FORMAT_INSTRUCTIONS_DICT_SUFFIX
        })

    def check_params_are_valid(self) -> None:
        super().check_params_are_valid()
        self.get_sk_base_public_key_class().check_params_are_valid(self)


SecurityKeyPrivateKeyParamsTypeVar = typing.TypeVar(
    'SecurityKeyPrivateKeyParamsTypeVar',
    bound='SecurityKeyPrivateKeyParams'
)


class SecurityKeyPrivateKeyParams(
    PrivateKeyParams, SecurityKeyPublicKeyParams
):
    """
    The parameters that represent the U2F/FIDO security key storing a private
    key.

    The names and iteration order of parameters of a *private* security key is:

    * The parameters of the public key.
    * ``application``: User-specified, typically ``ssh:`` (:any:`str`).
    * ``flags``: Flags (one byte).
    * ``key_handle``: The identifier of the private key on the security key
      (:any:`str`).
    * ``reserved``: Reserved by OpenSSH (:any:`bytes`).

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A parameter value from the above list is missing from
            ``params`` or does not have the correct type.
    """

    __FORMAT_INSTRUCTIONS_DICT_SUFFIX: typing.ClassVar[FormatInstructionsDict] = {
        'application': PascalStyleFormatInstruction.STRING,
        'flags': '>B',
        'key_handle': PascalStyleFormatInstruction.BYTES,
        'reserved': PascalStyleFormatInstruction.BYTES,
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType({
            **cls.get_sk_base_public_key_class().get_format_instructions_dict(),
            **SecurityKeyPrivateKeyParams.__FORMAT_INSTRUCTIONS_DICT_SUFFIX
        })

    @classmethod
    def generate_private_params(
        cls: typing.Type[SecurityKeyPrivateKeyParamsTypeVar],
        **kwargs: typing.Any
    ) -> SecurityKeyPrivateKeyParamsTypeVar:
        raise NotImplementedError()

    def get_flag(self, flag: SecurityKeyFlag) -> bool:
        """
        Returns whether the supplied :any:`SecurityKeyFlag` is set.
        """
        return typing.cast(int, self['flags'] & flag.value) != 0

    def set_flag(self, flag: SecurityKeyFlag, new_value: bool) -> None:
        """
        Sets the supplied :any:`SecurityKeyFlag` to the given value.
        """
        current_value = self.get_flag(flag)
        if new_value and not current_value:
            self['flags'] += flag.value
        elif not new_value and current_value:
            self['flags'] -= flag.value


class SecurityKey_ECDSA_NISTP256_PublicKeyParams(
    SecurityKeyPublicKeyParams,
    ECDSA_NISTP256_PublicKeyParams
):
    """
    The parameters that represent an ECDSA key on the ``nistp256`` curve that
    correspond to a private key stored on a security key.
    """

    @staticmethod
    def get_sk_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return ECDSA_NISTP256_PublicKeyParams


class SecurityKey_ECDSA_NISTP256_PrivateKeyParams(
    SecurityKeyPrivateKeyParams,
    SecurityKey_ECDSA_NISTP256_PublicKeyParams
):
    """
    The parameters that represent the security key storing an ECDSA key on the
    ``nistp256`` curve.
    """


class SecurityKey_Ed25519_PublicKeyParams(
    SecurityKeyPublicKeyParams,
    Ed25519PublicKeyParams
):
    """
    The parameters that represent an Ed25519 key that
    correspond to a private key stored on a security key.
    """

    @staticmethod
    def get_sk_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return Ed25519PublicKeyParams


class SecurityKey_Ed25519_PrivateKeyParams(
    SecurityKeyPrivateKeyParams,
    SecurityKey_Ed25519_PublicKeyParams
):
    """
    The parameters that represent the security key storing an Ed25519 key.
    """
