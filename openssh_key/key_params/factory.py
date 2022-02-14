"""
Methods to provide key params classes given OpenSSH key type names.
"""

import typing

from .cert import (Cert_DSS_PublicKeyParams,
                   Cert_ECDSA_NISTP256_PublicKeyParams,
                   Cert_ECDSA_NISTP384_PublicKeyParams,
                   Cert_ECDSA_NISTP521_PublicKeyParams,
                   Cert_Ed25519_PublicKeyParams, Cert_RSA_PublicKeyParams,
                   Cert_SecurityKey_ECDSA_NISTP256_PublicKeyParams,
                   Cert_SecurityKey_Ed25519_PublicKeyParams)
from .common import PrivateKeyParams, PublicKeyParams
from .dss import DSSPrivateKeyParams, DSSPublicKeyParams
from .ecdsa import (ECDSA_NISTP256_PrivateKeyParams,
                    ECDSA_NISTP256_PublicKeyParams,
                    ECDSA_NISTP384_PrivateKeyParams,
                    ECDSA_NISTP384_PublicKeyParams,
                    ECDSA_NISTP521_PrivateKeyParams,
                    ECDSA_NISTP521_PublicKeyParams)
from .ed25519 import Ed25519PrivateKeyParams, Ed25519PublicKeyParams
from .rsa import RSAPrivateKeyParams, RSAPublicKeyParams
from .sk import (SecurityKey_ECDSA_NISTP256_PrivateKeyParams,
                 SecurityKey_ECDSA_NISTP256_PublicKeyParams,
                 SecurityKey_Ed25519_PrivateKeyParams,
                 SecurityKey_Ed25519_PublicKeyParams)


class PublicPrivateKeyParamsClasses(typing.NamedTuple):
    """
    A public key class and its corresponding private key class.
    """

    publicKeyParamsClass: typing.Type[PublicKeyParams]
    """
    The public key class.
    """

    privateKeyParamsClass: typing.Optional[typing.Type[PrivateKeyParams]]
    """
    The private key class, if any.
    """


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
    'ecdsa-sha2-nistp256': PublicPrivateKeyParamsClasses(
        ECDSA_NISTP256_PublicKeyParams, ECDSA_NISTP256_PrivateKeyParams
    ),
    'ecdsa-sha2-nistp384': PublicPrivateKeyParamsClasses(
        ECDSA_NISTP384_PublicKeyParams, ECDSA_NISTP384_PrivateKeyParams
    ),
    'ecdsa-sha2-nistp521': PublicPrivateKeyParamsClasses(
        ECDSA_NISTP521_PublicKeyParams, ECDSA_NISTP521_PrivateKeyParams
    ),
    'sk-ecdsa-sha2-nistp256@openssh.com': PublicPrivateKeyParamsClasses(
        SecurityKey_ECDSA_NISTP256_PublicKeyParams,
        SecurityKey_ECDSA_NISTP256_PrivateKeyParams
    ),
    'sk-ssh-ed25519@openssh.com': PublicPrivateKeyParamsClasses(
        SecurityKey_Ed25519_PublicKeyParams,
        SecurityKey_Ed25519_PrivateKeyParams
    ),
    'ssh-rsa-cert-v01@openssh.com': PublicPrivateKeyParamsClasses(
        Cert_RSA_PublicKeyParams,
        None
    ),
    'ssh-ed25519-cert-v01@openssh.com': PublicPrivateKeyParamsClasses(
        Cert_Ed25519_PublicKeyParams,
        None,
    ),
    'ssh-dss-cert-v01@openssh.com': PublicPrivateKeyParamsClasses(
        Cert_DSS_PublicKeyParams,
        None
    ),
    'ecdsa-sha2-nistp256-cert-v01@openssh.com': PublicPrivateKeyParamsClasses(
        Cert_ECDSA_NISTP256_PublicKeyParams,
        None
    ),
    'ecdsa-sha2-nistp384-cert-v01@openssh.com': PublicPrivateKeyParamsClasses(
        Cert_ECDSA_NISTP384_PublicKeyParams,
        None
    ),
    'ecdsa-sha2-nistp521-cert-v01@openssh.com': PublicPrivateKeyParamsClasses(
        Cert_ECDSA_NISTP521_PublicKeyParams,
        None
    ),
    'sk-ssh-ed25519-cert-v01@openssh.com': PublicPrivateKeyParamsClasses(
        Cert_SecurityKey_Ed25519_PublicKeyParams,
        None
    ),
    'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com': PublicPrivateKeyParamsClasses(
        Cert_SecurityKey_ECDSA_NISTP256_PublicKeyParams,
        None
    )
}


def get_public_key_params_class(key_type: str) -> typing.Type[PublicKeyParams]:
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


def get_private_key_params_class(key_type: str) -> typing.Type[PrivateKeyParams]:
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
    private_key_params_class = _KEY_TYPE_MAPPING[key_type].privateKeyParamsClass
    if private_key_params_class is None:
        raise KeyError(
            'No subclass of PrivateKeyParams corresponds to the given key type name'
        )
    return private_key_params_class
