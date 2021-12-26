import secrets

import pytest

from openssh_key.key_params import (
    create_public_key_params,
    create_private_key_params,
    RSAPublicKeyParams,
    RSAPrivateKeyParams,
    Ed25519PublicKeyParams,
    Ed25519PrivateKeyParams,
    DSSPublicKeyParams,
    DSSPrivateKeyParams
)


def test_factory_rsa_public():
    assert create_public_key_params('ssh-rsa') == RSAPublicKeyParams


def test_factory_rsa_private():
    assert create_private_key_params('ssh-rsa') == RSAPrivateKeyParams


def test_factory_ed25519_public():
    assert create_public_key_params('ssh-ed25519') == Ed25519PublicKeyParams


def test_factory_ed25519_private():
    assert create_private_key_params('ssh-ed25519') == Ed25519PrivateKeyParams


def test_factory_dss_public():
    assert create_public_key_params('ssh-dss') == DSSPublicKeyParams


def test_factory_dss_private():
    assert create_private_key_params('ssh-dss') == DSSPrivateKeyParams


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
