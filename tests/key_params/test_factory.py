from openssh_key.key_params import (DSSPrivateKeyParams, DSSPublicKeyParams,
                                    Ed25519PrivateKeyParams,
                                    Ed25519PublicKeyParams,
                                    RSAPrivateKeyParams, RSAPublicKeyParams,
                                    create_private_key_params,
                                    create_public_key_params)


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
