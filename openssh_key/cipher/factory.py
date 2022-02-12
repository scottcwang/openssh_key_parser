"""
Methods to provide symmetric-key ciphers given OpenSSH cipher type names.
"""

import typing

from .common import Cipher
from .confidentiality import (AES128_CBCCipher, AES128_CTRCipher,
                              AES192_CBCCipher, AES192_CTRCipher,
                              AES256_CBCCipher, AES256_CTRCipher,
                              TripleDES_CBCCipher)
from .integrity import (AES128_GCMCipher, AES256_GCMCipher,
                        ChaCha20Poly1305Cipher)
from .none import NoneCipher

_CIPHER_MAPPING = {
    'none': NoneCipher,
    '3des-cbc': TripleDES_CBCCipher,
    'aes128-ctr': AES128_CTRCipher,
    'aes192-ctr': AES192_CTRCipher,
    'aes256-ctr': AES256_CTRCipher,
    'aes128-cbc': AES128_CBCCipher,
    'aes192-cbc': AES192_CBCCipher,
    'aes256-cbc': AES256_CBCCipher,
    'rijndael-cbc@lysator.liu.se': AES256_CBCCipher,
    'aes128-gcm@openssh.com': AES128_GCMCipher,
    'aes256-gcm@openssh.com': AES256_GCMCipher,
    'chacha20-poly1305@openssh.com': ChaCha20Poly1305Cipher,
}


def get_cipher_class(cipher_type: str) -> typing.Type[Cipher]:
    """Returns the class corresponding to the given cipher type name.

    Args:
        cipher_type
            The name of the OpenSSH private key cipher type.

    Returns:
        The subclass of :py:class:`Cipher` corresponding to the cipher type
        name.

    Raises:
        KeyError: There is no subclass of :py:class:`Cipher` corresponding to
            the given cipher type name.
    """
    return _CIPHER_MAPPING[cipher_type]
