import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from openssh_key.key_params import (ECDSA_NISTP256_PrivateKeyParams,
                                    ECDSA_NISTP256_PublicKeyParams,
                                    ECDSA_NISTP384_PrivateKeyParams,
                                    ECDSA_NISTP384_PublicKeyParams,
                                    ECDSA_NISTP521_PrivateKeyParams,
                                    ECDSA_NISTP521_PublicKeyParams,
                                    ECDSAPrivateKeyParams,
                                    ECDSAPublicKeyParams)
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction

nistp256_key = ec.generate_private_key(ec.SECP256R1())

nistp384_key = ec.generate_private_key(ec.SECP384R1())

nistp521_key = ec.generate_private_key(ec.SECP521R1())


PARAMS_TEST_CASES = [
    {
        'cls': ECDSA_NISTP256_PublicKeyParams,
        'format_instructions_dict': {
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'identifier': 'nistp256',
            'q': nistp256_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
        }],
        'invalid_values': [
            (
                {
                    'identifier': 'nistp256',
                    'q': b'\x00',
                },
                'The point does not lie on the elliptic curve indicated by '
                'the identifier'
            ),
            (
                {
                    'identifier': 'nistp384',
                    'q': nistp256_key.public_key().public_bytes(
                        Encoding.X962, PublicFormat.UncompressedPoint
                    ),
                },
                'The curve identifier encoded in the public key does not '
                'correspond to the key type'
            )
        ]
    },
    {
        'cls': ECDSA_NISTP256_PrivateKeyParams,
        'format_instructions_dict': {
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'd': PascalStyleFormatInstruction.MPINT,
        },
        'valid_values': [{
            'identifier': 'nistp256',
            'q': nistp256_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'd': nistp256_key.private_numbers().private_value,
        }],
    },
    {
        'cls': ECDSA_NISTP384_PublicKeyParams,
        'format_instructions_dict': {
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'identifier': 'nistp384',
            'q': nistp384_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
        }],
        'invalid_values': [
            (
                {
                    'identifier': 'nistp384',
                    'q': b'\x00',
                },
                'The point does not lie on the elliptic curve indicated by '
                'the identifier'
            ),
            (
                {
                    'identifier': 'nistp521',
                    'q': nistp521_key.public_key().public_bytes(
                        Encoding.X962, PublicFormat.UncompressedPoint
                    ),
                },
                'The curve identifier encoded in the public key does not '
                'correspond to the key type'
            )
        ]
    },
    {
        'cls': ECDSA_NISTP384_PrivateKeyParams,
        'format_instructions_dict': {
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'd': PascalStyleFormatInstruction.MPINT,
        },
        'valid_values': [{
            'identifier': 'nistp384',
            'q': nistp384_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'd': nistp384_key.private_numbers().private_value,
        }],
    },
    {
        'cls': ECDSA_NISTP521_PublicKeyParams,
        'format_instructions_dict': {
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
        },
        'valid_values': [{
            'identifier': 'nistp521',
            'q': nistp521_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
        }],
        'invalid_values': [
            (
                {
                    'identifier': 'nistp521',
                    'q': b'\x00',
                },
                'The point does not lie on the elliptic curve indicated by '
                'the identifier'
            ),
            (
                {
                    'identifier': 'nistp256',
                    'q': nistp521_key.public_key().public_bytes(
                        Encoding.X962, PublicFormat.UncompressedPoint
                    ),
                },
                'The curve identifier encoded in the public key does not '
                'correspond to the key type'
            )
        ]
    },
    {
        'cls': ECDSA_NISTP521_PrivateKeyParams,
        'format_instructions_dict': {
            'identifier': PascalStyleFormatInstruction.STRING,
            'q': PascalStyleFormatInstruction.BYTES,
            'd': PascalStyleFormatInstruction.MPINT,
        },
        'valid_values': [{
            'identifier': 'nistp521',
            'q': nistp521_key.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            ),
            'd': nistp521_key.private_numbers().private_value,
        }],
    },
]


def test_ecdsa_public_convert_from_unknown():
    with pytest.raises(NotImplementedError):
        ECDSAPublicKeyParams.convert_from('random')


def test_ecdsa_public_convert_from_cryptography_public():
    ecdsa_key_object = ec.generate_private_key(ec.SECP256R1()).public_key()
    converted = ECDSAPublicKeyParams.convert_from(ecdsa_key_object)
    assert type(converted) == ECDSA_NISTP256_PublicKeyParams
    assert converted == {
        'identifier': 'nistp256',
        'q': ecdsa_key_object.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        ),
    }


def test_ecdsa_public_convert_from_cryptography_private():
    ecdsa_key_object = ec.generate_private_key(ec.SECP256R1())
    converted = ECDSAPublicKeyParams.convert_from(ecdsa_key_object)
    assert type(converted) == ECDSA_NISTP256_PublicKeyParams
    assert converted == {
        'identifier': 'nistp256',
        'q': ecdsa_key_object.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        ),
    }


def test_ecdsa_public_convert_from_cryptography_public_different_curve():
    ecdsa_key_object = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(NotImplementedError):
        ECDSA_NISTP384_PublicKeyParams.convert_from(ecdsa_key_object)


def test_ecdsa_public_convert_to_cryptography_public():
    ecdsa_private = ECDSAPrivateKeyParams.generate_private_params()
    ecdsa_public = ECDSA_NISTP256_PublicKeyParams({
        'identifier': ecdsa_private['identifier'],
        'q': ecdsa_private['q']
    })
    converted = ecdsa_public.convert_to(ec.EllipticCurvePublicKey)
    assert isinstance(converted, ec.EllipticCurvePublicKey)
    assert type(converted.curve) == ec.SECP256R1
    assert converted.public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    ) == ecdsa_public['q']


def test_ecdsa_public_convert_to_cryptography_public_bad_curve_identifier():
    ecdsa_private = ECDSAPrivateKeyParams.generate_private_params()
    with pytest.warns(UserWarning):
        ecdsa_public = ECDSA_NISTP256_PublicKeyParams({
            'identifier': 'nistp384',
            'q': ecdsa_private['q']
        })
    with pytest.raises(
        NotImplementedError,
        match='The curve identifier encoded in the public key does not '
                       'correspond to the key type'
    ):
        ecdsa_public.convert_to(ec.EllipticCurvePublicKey)


def test_ecdsa_public_convert_to_cryptography_public_base_class():
    ecdsa_private = ECDSAPrivateKeyParams.generate_private_params()
    ecdsa_public = ECDSA_NISTP256_PublicKeyParams({
        'identifier': ecdsa_private['identifier'],
        'q': ecdsa_private['q']
    })
    converted = ecdsa_public.convert_to(ec.EllipticCurvePublicKey)
    assert isinstance(converted, ec.EllipticCurvePublicKey)
    assert type(converted.curve) == ec.SECP256R1
    assert converted.public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    ) == ecdsa_public['q']


def test_ecdsa_private_generate_private_params():
    with pytest.warns(None) as warnings_list:
        ecdsa_private_params = ECDSAPrivateKeyParams.generate_private_params()
    assert not warnings_list
    assert type(ecdsa_private_params) == ECDSA_NISTP256_PrivateKeyParams


def test_ecdsa_private_convert_from_unknown():
    with pytest.raises(NotImplementedError):
        ECDSAPrivateKeyParams.convert_from('random')


def test_ecdsa_private_convert_from_cryptography_private():
    ecdsa_key_object = ec.generate_private_key(ec.SECP256R1())
    converted = ECDSAPrivateKeyParams.convert_from(ecdsa_key_object)
    assert type(converted) == ECDSA_NISTP256_PrivateKeyParams
    assert converted == {
        'identifier': 'nistp256',
        'q': ecdsa_key_object.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        ),
        'd': ecdsa_key_object.private_numbers().private_value
    }


def test_ecdsa_private_convert_from_cryptography_private_different_curve():
    ecdsa_key_object = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(NotImplementedError):
        ECDSA_NISTP384_PrivateKeyParams.convert_from(ecdsa_key_object)


def test_ecdsa_private_convert_to_cryptography_private():
    ecdsa_private = ECDSAPrivateKeyParams.generate_private_params()
    converted = ecdsa_private.convert_to(ec.EllipticCurvePrivateKey)
    assert isinstance(converted, ec.EllipticCurvePrivateKey)
    assert type(converted.curve) == ec.SECP256R1
    assert converted.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    ) == ecdsa_private['q']
    assert converted.private_numbers().private_value == ecdsa_private['d']


def test_ecdsa_private_convert_to_cryptography_public():
    ecdsa_private = ECDSAPrivateKeyParams.generate_private_params()
    converted = ecdsa_private.convert_to(ec.EllipticCurvePublicKey)
    assert isinstance(converted, ec.EllipticCurvePublicKey)
    assert type(converted.curve) == ec.SECP256R1
    assert converted.public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    ) == ecdsa_private['q']


def test_ecdsa_public_convert_to_not_implemented():
    ecdsa_private = ECDSAPrivateKeyParams.generate_private_params()
    with pytest.raises(NotImplementedError):
        assert ecdsa_private.convert_to(type)
