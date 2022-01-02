import typing

from .common import (
    PublicKeyParams,
    PrivateKeyParams
)
from .rsa import (
    RSAPublicKeyParams,
    RSAPrivateKeyParams
)
from .ed25519 import (
    Ed25519PublicKeyParams,
    Ed25519PrivateKeyParams
)
from .dss import (
    DSSPublicKeyParams,
    DSSPrivateKeyParams
)
from .ecdsa import (
    ECDSA_NISTP256_PublicKeyParams,
    ECDSA_NISTP256_PrivateKeyParams,
    ECDSA_NISTP384_PublicKeyParams,
    ECDSA_NISTP384_PrivateKeyParams,
    ECDSA_NISTP521_PublicKeyParams,
    ECDSA_NISTP521_PrivateKeyParams
)


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
    'ssh-dss': PublicPrivateKeyParamsClasses(
        DSSPublicKeyParams, DSSPrivateKeyParams
    ),
    'ssh-ecdsa-nistp256': PublicPrivateKeyParamsClasses(
        ECDSA_NISTP256_PublicKeyParams, ECDSA_NISTP256_PrivateKeyParams
    ),
    'ssh-ecdsa-nistp384': PublicPrivateKeyParamsClasses(
        ECDSA_NISTP384_PublicKeyParams, ECDSA_NISTP384_PrivateKeyParams
    ),
    'ssh-ecdsa-nistp521': PublicPrivateKeyParamsClasses(
        ECDSA_NISTP521_PublicKeyParams, ECDSA_NISTP521_PrivateKeyParams
    )
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
