import secrets

import pytest
from openssh_key.key_params import (Ed25519PrivateKeyParams,
                                    Ed25519PublicKeyParams,
                                    RSAPrivateKeyParams)


def test_str():
    public_bytes = secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
    ed25519_private_dict = {
        'public': public_bytes,
        'private_public': secrets.token_bytes(
            Ed25519PublicKeyParams.KEY_SIZE
        ) + public_bytes
    }
    ed25519_private = Ed25519PrivateKeyParams(ed25519_private_dict)
    assert str(ed25519_private) == str(ed25519_private_dict)


def test_convert_to_not_class():
    rsa_private = RSAPrivateKeyParams.generate_private_params()
    with pytest.raises(ValueError):
        assert rsa_private.convert_to('not class')
