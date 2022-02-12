"""
Methods to provide key derivation functions given OpenSSH key derivation
function type names.
"""

import typing

from .bcrypt_options import BcryptKDFOptions
from .common import KDFOptions
from .none import NoneKDFOptions

_KDF_MAPPING = {
    'none': NoneKDFOptions,
    'bcrypt': BcryptKDFOptions
}


def get_kdf_options_class(kdf_type: str) -> typing.Type[KDFOptions]:
    """Returns the class corresponding to the given key derivation function
    type name.

    Args:
        kdf_type
            The name of the OpenSSH private key key derivation function type.

    Returns:
        The subclass of :py:class:`KDF` corresponding to the key derivation
        function type name.

    Raises:
        KeyError: There is no subclass of :py:class:`KDF` corresponding to
            the given key derivation function type name.
    """
    return _KDF_MAPPING[kdf_type]
