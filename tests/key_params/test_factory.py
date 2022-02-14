import pytest

from openssh_key.key_params import (DSSPrivateKeyParams, DSSPublicKeyParams,
                                    Ed25519PrivateKeyParams,
                                    Ed25519PublicKeyParams,
                                    RSAPrivateKeyParams, RSAPublicKeyParams,
                                    ECDSA_NISTP256_PrivateKeyParams,
                                    ECDSA_NISTP256_PublicKeyParams,
                                    ECDSA_NISTP384_PrivateKeyParams,
                                    ECDSA_NISTP384_PublicKeyParams,
                                    ECDSA_NISTP521_PrivateKeyParams,
                                    ECDSA_NISTP521_PublicKeyParams,
                                    SecurityKey_ECDSA_NISTP256_PrivateKeyParams,
                                    SecurityKey_ECDSA_NISTP256_PublicKeyParams,
                                    SecurityKey_Ed25519_PrivateKeyParams,
                                    SecurityKey_Ed25519_PublicKeyParams,
                                    Cert_RSA_PublicKeyParams,
                                    Cert_Ed25519_PublicKeyParams,
                                    Cert_DSS_PublicKeyParams,
                                    Cert_ECDSA_NISTP256_PublicKeyParams,
                                    Cert_ECDSA_NISTP384_PublicKeyParams,
                                    Cert_ECDSA_NISTP521_PublicKeyParams,
                                    Cert_SecurityKey_Ed25519_PublicKeyParams,
                                    Cert_SecurityKey_ECDSA_NISTP256_PublicKeyParams,
                                    get_private_key_params_class,
                                    get_public_key_params_class)


def test_factory_rsa_public():
    assert get_public_key_params_class('ssh-rsa') == RSAPublicKeyParams


def test_factory_rsa_private():
    assert get_private_key_params_class('ssh-rsa') == RSAPrivateKeyParams


def test_factory_ed25519_public():
    assert get_public_key_params_class('ssh-ed25519') == Ed25519PublicKeyParams


def test_factory_ed25519_private():
    assert get_private_key_params_class('ssh-ed25519') == Ed25519PrivateKeyParams


def test_factory_dss_public():
    assert get_public_key_params_class('ssh-dss') == DSSPublicKeyParams


def test_factory_dss_private():
    assert get_private_key_params_class('ssh-dss') == DSSPrivateKeyParams


def test_factory_ecdsa_nistp256_public():
    assert get_public_key_params_class(
        'ecdsa-sha2-nistp256') == ECDSA_NISTP256_PublicKeyParams


def test_factory_ecdsa_nistp256_private():
    assert get_private_key_params_class(
        'ecdsa-sha2-nistp256') == ECDSA_NISTP256_PrivateKeyParams


def test_factory_ecdsa_nistp384_public():
    assert get_public_key_params_class(
        'ecdsa-sha2-nistp384') == ECDSA_NISTP384_PublicKeyParams


def test_factory_ecdsa_nistp384_private():
    assert get_private_key_params_class(
        'ecdsa-sha2-nistp384') == ECDSA_NISTP384_PrivateKeyParams


def test_factory_ecdsa_nistp521_public():
    assert get_public_key_params_class(
        'ecdsa-sha2-nistp521') == ECDSA_NISTP521_PublicKeyParams


def test_factory_ecdsa_nistp521_private():
    assert get_private_key_params_class(
        'ecdsa-sha2-nistp521') == ECDSA_NISTP521_PrivateKeyParams


def test_factory_sk_ecdsa_nistp256_public():
    assert get_public_key_params_class(
        'sk-ecdsa-sha2-nistp256@openssh.com') == SecurityKey_ECDSA_NISTP256_PublicKeyParams


def test_factory_sk_ecdsa_nistp256_private():
    assert get_private_key_params_class(
        'sk-ecdsa-sha2-nistp256@openssh.com') == SecurityKey_ECDSA_NISTP256_PrivateKeyParams


def test_factory_sk_ed25519_public():
    assert get_public_key_params_class(
        'sk-ssh-ed25519@openssh.com') == SecurityKey_Ed25519_PublicKeyParams


def test_factory_sk_ed25519_private():
    assert get_private_key_params_class(
        'sk-ssh-ed25519@openssh.com') == SecurityKey_Ed25519_PrivateKeyParams


def test_factory_cert_rsa_public():
    assert get_public_key_params_class(
        'ssh-rsa-cert-v01@openssh.com') == Cert_RSA_PublicKeyParams


def test_factory_cert_rsa_private():
    with pytest.raises(
        KeyError,
        match='No subclass of PrivateKeyParams corresponds to the given key type name'
    ):
        get_private_key_params_class('ssh-rsa-cert-v01@openssh.com')


def test_factory_cert_ed25519_public():
    assert get_public_key_params_class(
        'ssh-ed25519-cert-v01@openssh.com') == Cert_Ed25519_PublicKeyParams


def test_factory_cert_ed25519_private():
    with pytest.raises(
        KeyError,
        match='No subclass of PrivateKeyParams corresponds to the given key type name'
    ):
        get_private_key_params_class('ssh-ed25519-cert-v01@openssh.com')


def test_factory_cert_dss_public():
    assert get_public_key_params_class(
        'ssh-dss-cert-v01@openssh.com') == Cert_DSS_PublicKeyParams


def test_factory_cert_dss_private():
    with pytest.raises(
        KeyError,
        match='No subclass of PrivateKeyParams corresponds to the given key type name'
    ):
        get_private_key_params_class('ssh-dss-cert-v01@openssh.com')


def test_factory_cert_ecdsa_nistp256_public():
    assert get_public_key_params_class(
        'ecdsa-sha2-nistp256-cert-v01@openssh.com') == Cert_ECDSA_NISTP256_PublicKeyParams


def test_factory_cert_ecdsa_nistp256_private():
    with pytest.raises(
        KeyError,
        match='No subclass of PrivateKeyParams corresponds to the given key type name'
    ):
        get_private_key_params_class('ecdsa-sha2-nistp256-cert-v01@openssh.com')


def test_factory_cert_ecdsa_nistp384_public():
    assert get_public_key_params_class(
        'ecdsa-sha2-nistp384-cert-v01@openssh.com') == Cert_ECDSA_NISTP384_PublicKeyParams


def test_factory_cert_ecdsa_nistp384_private():
    with pytest.raises(
        KeyError,
        match='No subclass of PrivateKeyParams corresponds to the given key type name'
    ):
        get_private_key_params_class('ecdsa-sha2-nistp384-cert-v01@openssh.com')


def test_factory_cert_ecdsa_nistp521_public():
    assert get_public_key_params_class(
        'ecdsa-sha2-nistp521-cert-v01@openssh.com') == Cert_ECDSA_NISTP521_PublicKeyParams


def test_factory_cert_ecdsa_nistp521_private():
    with pytest.raises(
        KeyError,
        match='No subclass of PrivateKeyParams corresponds to the given key type name'
    ):
        get_private_key_params_class('ecdsa-sha2-nistp521-cert-v01@openssh.com')


def test_factory_cert_sk_ed25519_public():
    assert get_public_key_params_class(
        'sk-ssh-ed25519-cert-v01@openssh.com') == Cert_SecurityKey_Ed25519_PublicKeyParams


def test_factory_cert_sk_ed25519_private():
    with pytest.raises(
        KeyError,
        match='No subclass of PrivateKeyParams corresponds to the given key type name'
    ):
        get_private_key_params_class('sk-ssh-ed25519-cert-v01@openssh.com')


def test_factory_cert_sk_ecdsa_nistp256_public():
    assert get_public_key_params_class(
        'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com') == Cert_SecurityKey_ECDSA_NISTP256_PublicKeyParams


def test_factory_cert_sk_ecdsa_nistp256_private():
    with pytest.raises(
        KeyError,
        match='No subclass of PrivateKeyParams corresponds to the given key type name'
    ):
        get_private_key_params_class(
            'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com')
