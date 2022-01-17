import secrets
from datetime import datetime

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from openssh_key.key import PublicKey
from openssh_key.key_params.cert import (
    Cert_DSS_PublicKeyParams, Cert_ECDSA_NISTP256_PublicKeyParams,
    Cert_ECDSA_NISTP384_PublicKeyParams, Cert_ECDSA_NISTP521_PublicKeyParams,
    Cert_Ed25519_PublicKeyParams, Cert_RSA_PublicKeyParams,
    Cert_SecurityKey_ECDSA_NISTP256_PublicKeyParams,
    Cert_SecurityKey_Ed25519_PublicKeyParams, CertCriticalOption,
    CertPrincipalType)
from openssh_key.key_params.ed25519 import (Ed25519PrivateKeyParams,
                                            Ed25519PublicKeyParams)
from openssh_key.key_params.rsa import RSAPrivateKeyParams
from openssh_key.pascal_style_byte_stream import (PascalStyleByteStream,
                                                  PascalStyleFormatInstruction)

certificate_authority_key_bytes = PublicKey(
    {
        'key_type': 'ssh-rsa'
    },
    RSAPrivateKeyParams.generate_private_params(),
    {}
).pack_public_bytes()


def get_test_cert_params():
    return Cert_RSA_PublicKeyParams({
        'nonce': 'a',
        'e': 1,
        'n': 2,
        'serial': 3,
        'type': 1,
        'key_id': 'test',
        'valid_principals': b'\x00\x00\x00\x01a',
        'valid_after': 4,
        'valid_before': 5,
        'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
        'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
        'reserved': '',
        'signature_key': certificate_authority_key_bytes,
        'signature': b'f'
    })


test_cert_key_bytes = PublicKey(
    {
        'key_type': 'ssh-rsa-cert-v01@openssh.com'
    },
    get_test_cert_params(),
    {}
).pack_public_bytes()


PARAMS_TEST_CASES = [
    {
        'cls': Cert_RSA_PublicKeyParams,
        'format_instructions_dict': {
            'nonce': PascalStyleFormatInstruction.STRING,
            'e': PascalStyleFormatInstruction.MPINT,
            'n': PascalStyleFormatInstruction.MPINT,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
            'signature': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'nonce': 'a',
            'e': 1,
            'n': 2,
            'serial': 3,
            'type': 1,
            'key_id': 'test',
            'valid_principals': b'\x00\x00\x00\x01a',
            'valid_after': 4,
            'valid_before': 5,
            'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'reserved': '',
            'signature_key': certificate_authority_key_bytes,
            'signature': b'f'
        }],
        'invalid_values': [
            (
                {
                    'nonce': 'a',
                    'e': 1,
                    'n': 2,
                    'serial': 3,
                    'type': 3,
                    'key_id': 'test',
                    'valid_principals': b'\x00\x00\x00\x01a',
                    'valid_after': 4,
                    'valid_before': 5,
                    'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'reserved': '',
                    'signature_key': certificate_authority_key_bytes,
                    'signature': b'f'
                },
                'Not a valid certificate principal type'
            ),
            (
                {
                    'nonce': 'a',
                    'e': 1,
                    'n': 2,
                    'serial': 3,
                    'type': 3,
                    'key_id': 'test',
                    'valid_principals': b'invalid',
                    'valid_after': 4,
                    'valid_before': 5,
                    'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'reserved': '',
                    'signature_key': certificate_authority_key_bytes,
                    'signature': b'f'
                },
                'Invalid format for certificate principals list'
            ),
            (
                {
                    'nonce': 'a',
                    'e': 1,
                    'n': 2,
                    'serial': 3,
                    'type': 3,
                    'key_id': 'test',
                    'valid_principals': b'\x00\x00\x00\x01a',
                    'valid_after': 4,
                    'valid_before': 5,
                    'critical_options': b'invalid',
                    'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'reserved': '',
                    'signature_key': certificate_authority_key_bytes,
                    'signature': b'f'
                },
                'Invalid format for critical options list'
            ),
            (
                {
                    'nonce': 'a',
                    'e': 1,
                    'n': 2,
                    'serial': 3,
                    'type': 3,
                    'key_id': 'test',
                    'valid_principals': b'\x00\x00\x00\x01a',
                    'valid_after': 4,
                    'valid_before': 5,
                    'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'extensions': b'invalid',
                    'reserved': '',
                    'signature_key': certificate_authority_key_bytes,
                    'signature': b'f'
                },
                'Invalid format for extensions list'
            ),
            (
                {
                    'nonce': 'a',
                    'e': 1,
                    'n': 2,
                    'serial': 3,
                    'type': 1,
                    'key_id': 'test',
                    'valid_principals': b'\x00\x00\x00\x01a',
                    'valid_after': 4,
                    'valid_before': 5,
                    'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'reserved': '',
                    'signature_key': test_cert_key_bytes,
                    'signature': b'd'
                },
                'The certificate authority must not be a certificate'
            ),
            (
                {
                    'nonce': 'a',
                    'e': 1,
                    'n': 2,
                    'serial': 3,
                    'type': 1,
                    'key_id': 'test',
                    'valid_principals': b'\x00\x00\x00\x01a',
                    'valid_after': 4,
                    'valid_before': 5,
                    'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
                    'reserved': '',
                    'signature_key': b'invalid',
                    'signature': b'd'
                },
                'Certificate authority is not a valid key'
            ),
        ]
    },
    {
        'cls': Cert_Ed25519_PublicKeyParams,
        'format_instructions_dict': {
            'nonce': PascalStyleFormatInstruction.STRING,
            'public': PascalStyleFormatInstruction.BYTES,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
            'signature': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'nonce': 'a',
            'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE),
            'serial': 3,
            'type': 1,
            'key_id': 'test',
            'valid_principals': b'\x00\x00\x00\x01a',
            'valid_after': 4,
            'valid_before': 5,
            'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'reserved': '',
            'signature_key': certificate_authority_key_bytes,
            'signature': b'f'
        }]
    },
    {
        'cls': Cert_DSS_PublicKeyParams,
        'format_instructions_dict': {
            'nonce': PascalStyleFormatInstruction.STRING,
            'p': PascalStyleFormatInstruction.MPINT,
            'q': PascalStyleFormatInstruction.MPINT,
            'g': PascalStyleFormatInstruction.MPINT,
            'y': PascalStyleFormatInstruction.MPINT,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
            'signature': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'nonce': 'a',
            'p': 1,
            'q': 2,
            'g': 3,
            'y': 4,
            'serial': 3,
            'type': 1,
            'key_id': 'test',
            'valid_principals': b'\x00\x00\x00\x01a',
            'valid_after': 4,
            'valid_before': 5,
            'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'reserved': '',
            'signature_key': certificate_authority_key_bytes,
            'signature': b'f'
        }]
    },
    {
        'cls': Cert_ECDSA_NISTP256_PublicKeyParams,
        'format_instructions_dict': {
            'nonce': PascalStyleFormatInstruction.STRING,
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
            'signature': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'nonce': 'a',
            'identifier': 'nistp256',
            'q': ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'serial': 3,
            'type': 1,
            'key_id': 'test',
            'valid_principals': b'\x00\x00\x00\x01a',
            'valid_after': 4,
            'valid_before': 5,
            'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'reserved': '',
            'signature_key': certificate_authority_key_bytes,
            'signature': b'f'
        }]
    },
    {
        'cls': Cert_ECDSA_NISTP384_PublicKeyParams,
        'format_instructions_dict': {
            'nonce': PascalStyleFormatInstruction.STRING,
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
            'signature': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'nonce': 'a',
            'identifier': 'nistp384',
            'q': ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'serial': 3,
            'type': 1,
            'key_id': 'test',
            'valid_principals': b'\x00\x00\x00\x01a',
            'valid_after': 4,
            'valid_before': 5,
            'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'reserved': '',
            'signature_key': certificate_authority_key_bytes,
            'signature': b'f'
        }]
    },
    {
        'cls': Cert_ECDSA_NISTP521_PublicKeyParams,
        'format_instructions_dict': {
            'nonce': PascalStyleFormatInstruction.STRING,
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
            'signature': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'nonce': 'a',
            'identifier': 'nistp521',
            'q': ec.generate_private_key(ec.SECP521R1()).public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'serial': 3,
            'type': 1,
            'key_id': 'test',
            'valid_principals': b'\x00\x00\x00\x01a',
            'valid_after': 4,
            'valid_before': 5,
            'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'reserved': '',
            'signature_key': certificate_authority_key_bytes,
            'signature': b'f'
        }]
    },
    {
        'cls': Cert_SecurityKey_Ed25519_PublicKeyParams,
        'format_instructions_dict': {
            'nonce': PascalStyleFormatInstruction.STRING,
            'public': PascalStyleFormatInstruction.BYTES,
            'application': PascalStyleFormatInstruction.STRING,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
            'signature': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'nonce': 'a',
            'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE),
            'application': 'ssh:',
            'serial': 3,
            'type': 1,
            'key_id': 'test',
            'valid_principals': b'\x00\x00\x00\x01a',
            'valid_after': 4,
            'valid_before': 5,
            'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'reserved': '',
            'signature_key': certificate_authority_key_bytes,
            'signature': b'f'
        }]
    },
    {
        'cls': Cert_SecurityKey_ECDSA_NISTP256_PublicKeyParams,
        'format_instructions_dict': {
            'nonce': PascalStyleFormatInstruction.STRING,
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'application': PascalStyleFormatInstruction.STRING,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
            'signature': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'nonce': 'a',
            'identifier': 'nistp256',
            'q': ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'application': 'ssh:',
            'serial': 3,
            'type': 1,
            'key_id': 'test',
            'valid_principals': b'\x00\x00\x00\x01a',
            'valid_after': 4,
            'valid_before': 5,
            'critical_options': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'extensions': b'\x00\x00\x00\x01b\x00\x00\x00\x01c',
            'reserved': '',
            'signature_key': certificate_authority_key_bytes,
            'signature': b'f'
        }]
    },
]


def test_type():
    cert_params = get_test_cert_params()
    assert cert_params.get_type() == CertPrincipalType.USER
    cert_params.set_type(CertPrincipalType.HOST)
    assert cert_params.get_type() == CertPrincipalType.HOST
    assert cert_params['type'] == 2


def test_valid_principals():
    cert_params = get_test_cert_params()
    assert cert_params.get_valid_principals() == ['a']
    cert_params.set_valid_principals(['b', 'c'])
    assert cert_params.get_valid_principals() == ['b', 'c']
    assert cert_params['valid_principals'] == b'\x00\x00\x00\x01b\x00\x00\x00\x01c'


def test_valid_after():
    cert_params = get_test_cert_params()
    assert cert_params.get_valid_after() == datetime.fromtimestamp(4)
    cert_params.set_valid_after(datetime.fromtimestamp(6))
    assert cert_params.get_valid_after() == datetime.fromtimestamp(6)
    assert cert_params['valid_after'] == 6


def test_valid_before():
    cert_params = get_test_cert_params()
    assert cert_params.get_valid_before() == datetime.fromtimestamp(5)
    cert_params.set_valid_before(datetime.fromtimestamp(7))
    assert cert_params.get_valid_before() == datetime.fromtimestamp(7)
    assert cert_params['valid_before'] == 7


def test_get_critical_option_str_option():
    cert_params = get_test_cert_params()
    cert_params['critical_options'] = \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x01d\x00\x00\x00\x01e'
    assert cert_params.get_critical_option('b') == b'c'
    assert cert_params.get_critical_option('d') == b'e'


def test_get_critical_option_str_option_nonexistent():
    cert_params = get_test_cert_params()
    assert cert_params.get_critical_option('c') is None


def test_get_critical_option_enum_option():
    cert_params = get_test_cert_params()
    cert_params['critical_options'] = \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x0dforce-command\x00\x00\x00\x01e'
    assert cert_params.get_critical_option(
        CertCriticalOption.FORCE_COMMAND
    ) == b'e'


def test_get_critical_option_enum_option_wrong_type():
    cert_params = get_test_cert_params()
    cert_params['type'] = 2
    with pytest.raises(
        ValueError,
        match='Option is not valid for the principal types of this certificate'
    ):
        cert_params.get_critical_option(CertCriticalOption.FORCE_COMMAND)


def test_get_critical_option_duplicate_option():
    cert_params = get_test_cert_params()
    cert_params['critical_options'] = \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x01b\x00\x00\x00\x01e'
    with pytest.warns(UserWarning, match='Duplicate option b in critical_options'):
        assert cert_params.get_critical_option('b') == b'e'


def test_set_critical_option_different_option_before():
    cert_params = get_test_cert_params()
    cert_params.set_critical_option('a', b'e')
    assert cert_params['critical_options'] == \
        b'\x00\x00\x00\x01a\x00\x00\x00\x01e' \
        + b'\x00\x00\x00\x01b\x00\x00\x00\x01c'


def test_set_critical_option_different_option_after():
    cert_params = get_test_cert_params()
    cert_params.set_critical_option('d', b'e')
    assert cert_params['critical_options'] == \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x01d\x00\x00\x00\x01e'


def test_set_critical_option_same_option():
    cert_params = get_test_cert_params()
    cert_params.set_critical_option('b', b'e')
    assert cert_params['critical_options'] == \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01e'


def test_set_critical_option_enum_option():
    cert_params = get_test_cert_params()
    cert_params.set_critical_option(
        CertCriticalOption.FORCE_COMMAND,
        b'e'
    )
    assert cert_params['critical_options'] == \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x0dforce-command\x00\x00\x00\x01e'


def test_set_critical_option_enum_option_wrong_type():
    cert_params = get_test_cert_params()
    cert_params['type'] = 2
    with pytest.raises(
        ValueError,
        match='Option force-command is not valid for the principal types of this certificate'
    ):
        cert_params.set_critical_option(
            CertCriticalOption.FORCE_COMMAND,
            b'e'
        )
    assert cert_params['critical_options'] == \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c'


def test_get_extension_str_option():
    cert_params = get_test_cert_params()
    assert cert_params.get_extension_value('b') == b'c'


def test_get_extension_str_option_nonexistent():
    cert_params = get_test_cert_params()
    assert cert_params.get_extension_value('c') is None


def test_get_extension_enum_option():
    cert_params = get_test_cert_params()
    cert_params['extensions'] = \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x0dforce-command\x00\x00\x00\x01e'
    assert cert_params.get_extension_value(
        CertCriticalOption.FORCE_COMMAND
    ) == b'e'


def test_get_extension_enum_option_wrong_type():
    cert_params = get_test_cert_params()
    cert_params['type'] = 2
    with pytest.raises(
        ValueError,
        match='Option is not valid for the principal types of this certificate'
    ):
        cert_params.get_extension_value(CertCriticalOption.FORCE_COMMAND)


def test_get_extension_duplicate_option():
    cert_params = get_test_cert_params()
    cert_params['extensions'] = \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x01b\x00\x00\x00\x01e'
    with pytest.warns(UserWarning, match='Duplicate option b in extensions'):
        cert_params.get_extension_value('b')


def test_set_extension_different_option_before():
    cert_params = get_test_cert_params()
    cert_params.set_extension_value('a', b'e')
    assert cert_params['extensions'] == \
        b'\x00\x00\x00\x01a\x00\x00\x00\x01e' \
        + b'\x00\x00\x00\x01b\x00\x00\x00\x01c'


def test_set_extension_different_option_after():
    cert_params = get_test_cert_params()
    cert_params.set_extension_value('d', b'e')
    assert cert_params['extensions'] == \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x01d\x00\x00\x00\x01e'


def test_set_extension_same_option():
    cert_params = get_test_cert_params()
    cert_params.set_extension_value('b', b'e')
    assert cert_params['extensions'] == \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01e'


def test_set_extension_enum_option():
    cert_params = get_test_cert_params()
    cert_params.set_extension_value(
        CertCriticalOption.FORCE_COMMAND,
        b'e'
    )
    assert cert_params['extensions'] == \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c' \
        + b'\x00\x00\x00\x0dforce-command\x00\x00\x00\x01e'


def test_set_extension_enum_option_wrong_type():
    cert_params = get_test_cert_params()
    cert_params['type'] = 2
    with pytest.raises(
        ValueError,
        match='Option force-command is not valid for the principal types of this certificate'
    ):
        cert_params.set_extension_value(
            CertCriticalOption.FORCE_COMMAND,
            b'e'
        )
    assert cert_params['extensions'] == \
        b'\x00\x00\x00\x01b\x00\x00\x00\x01c'


def test_pack_signed_bytes():
    cert_params = get_test_cert_params()
    byte_stream = PascalStyleByteStream()
    byte_stream.write_from_format_instructions_dict(
        {
            'nonce': PascalStyleFormatInstruction.STRING,
            'e': PascalStyleFormatInstruction.MPINT,
            'n': PascalStyleFormatInstruction.MPINT,
            'serial': '>Q',
            'type': '>I',
            'key_id': PascalStyleFormatInstruction.STRING,
            'valid_principals': PascalStyleFormatInstruction.BYTES,
            'valid_after': '>Q',
            'valid_before': '>Q',
            'critical_options': PascalStyleFormatInstruction.BYTES,
            'extensions': PascalStyleFormatInstruction.BYTES,
            'reserved': PascalStyleFormatInstruction.STRING,
            'signature_key': PascalStyleFormatInstruction.BYTES,
        },
        cert_params
    )
    assert cert_params.pack_signed_bytes() == byte_stream.getvalue()


def test_get_signature_key():
    assert get_test_cert_params().get_signature_key() == PublicKey.from_bytes(
        certificate_authority_key_bytes
    )


def test_set_signature_key():
    cert_params = get_test_cert_params()
    new_ca = PublicKey(
        {
            'key_type': 'ssh-ed25519'
        },
        Ed25519PrivateKeyParams.generate_private_params(),
        {}
    )
    cert_params.set_signature_key(new_ca)
    assert cert_params['signature_key'] == new_ca.pack_public_bytes()


def test_set_signature_key_cert():
    cert_params = get_test_cert_params()
    new_ca = PublicKey(
        {
            'key_type': 'ssh-rsa-cert-v01@openssh.com'
        },
        get_test_cert_params(),
        {}
    )
    with pytest.raises(
        ValueError,
        match='The certificate authority must not be a certificate'
    ):
        cert_params.set_signature_key(new_ca)
