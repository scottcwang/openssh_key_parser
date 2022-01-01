import pytest
import secrets
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import nacl.signing

from openssh_key.key_params import (
    Ed25519PrivateKeyParams,
    Ed25519PublicKeyParams
)
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction

test_cases_public_bytes = secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)

PARAMS_TEST_CASES = [
    {
        'cls': Ed25519PublicKeyParams,
        'format_instructions_dict': {
            'public': PascalStyleFormatInstruction.BYTES
        },
        'valid_values': [{
            'public': test_cases_public_bytes
        }],
        'invalid_values': [(
            {
                'public': secrets.token_bytes(
                    Ed25519PublicKeyParams.KEY_SIZE - 1
                )
            },
            'Public key not of length ' + str(Ed25519PublicKeyParams.KEY_SIZE)
        )]
    },
    {
        'cls': Ed25519PrivateKeyParams,
        'format_instructions_dict': {
            'public': PascalStyleFormatInstruction.BYTES,
            'private_public': PascalStyleFormatInstruction.BYTES
        },
        'valid_values': [{
            'public': test_cases_public_bytes,
            'private_public': secrets.token_bytes(
                Ed25519PublicKeyParams.KEY_SIZE
            ) + test_cases_public_bytes
        }],
        'invalid_values': [
            (
                {
                    'public': test_cases_public_bytes,
                    'private_public': secrets.token_bytes(
                        Ed25519PublicKeyParams.KEY_SIZE
                    ) + b'\x00' * Ed25519PublicKeyParams.KEY_SIZE
                },
                'Public key does not match'
            ), (
                {
                    'public': test_cases_public_bytes,
                    'private_public': secrets.token_bytes(
                        Ed25519PublicKeyParams.KEY_SIZE - 1
                    ) + test_cases_public_bytes
                },
                'Private key not of length '
                + str(Ed25519PublicKeyParams.KEY_SIZE)
            )
        ]
    }
]


def test_ed25519_public_convert_from_unknown():
    with pytest.raises(NotImplementedError):
        Ed25519PublicKeyParams.convert_from('random')


def test_ed25519_public_convert_from_cryptography_public():
    ed25519_key_object = ed25519.Ed25519PrivateKey.generate().public_key()
    converted = Ed25519PublicKeyParams.convert_from(ed25519_key_object)
    assert type(converted) == Ed25519PublicKeyParams
    assert converted == {
        'public': ed25519_key_object.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    }


def test_ed25519_public_convert_from_bytes_public():
    ed25519_key_object = secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
    converted = Ed25519PublicKeyParams.convert_from(ed25519_key_object)
    assert type(converted) == Ed25519PublicKeyParams
    assert converted == {
        'public': ed25519_key_object
    }


def test_ed25519_public_convert_from_pynacl_public():
    ed25519_key_object = nacl.signing.SigningKey.generate().verify_key
    converted = Ed25519PublicKeyParams.convert_from(ed25519_key_object)
    assert type(converted) == Ed25519PublicKeyParams
    assert converted == {
        'public': bytes(ed25519_key_object)
    }


def test_ed25519_public_convert_from_cryptography_private():
    ed25519_key_object = ed25519.Ed25519PrivateKey.generate()
    converted = Ed25519PublicKeyParams.convert_from(ed25519_key_object)
    assert type(converted) == Ed25519PublicKeyParams
    public_bytes = ed25519_key_object.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    assert converted == {
        'public': public_bytes
    }


def test_ed25519_public_convert_from_pynacl_private():
    ed25519_key_object = nacl.signing.SigningKey.generate()
    converted = Ed25519PublicKeyParams.convert_from(ed25519_key_object)
    assert type(converted) == Ed25519PublicKeyParams
    public_bytes = ed25519_key_object.verify_key
    assert converted == {
        'public': bytes(public_bytes)
    }


def test_ed25519_public_convert_to_cryptography_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    ed25519_public = Ed25519PublicKeyParams({
        'public': ed25519_private['public']
    })
    converted = ed25519_public.convert_to(ed25519.Ed25519PublicKey)
    assert isinstance(converted, ed25519.Ed25519PublicKey)
    assert converted.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) == ed25519_public['public']


def test_ed25519_public_convert_to_bytes_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    ed25519_public = Ed25519PublicKeyParams({
        'public': ed25519_private['public']
    })
    converted = ed25519_public.convert_to(bytes)
    assert type(converted) == bytes
    assert converted == ed25519_public['public']


def test_ed25519_public_convert_to_pynacl_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    ed25519_public = Ed25519PublicKeyParams({
        'public': ed25519_private['public']
    })
    converted = ed25519_public.convert_to(nacl.signing.VerifyKey)
    assert type(converted) == nacl.signing.VerifyKey
    assert bytes(converted) == ed25519_public['public']


def test_ed25519_public_convert_to_missing_pynacl(mocker):
    mocker.patch.dict(sys.modules, {'nacl': None})
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    ed25519_public = Ed25519PublicKeyParams({
        'public': ed25519_private['public']
    })
    with pytest.raises(NotImplementedError):
        ed25519_public.convert_to(nacl.signing.VerifyKey)


def test_ed25519_private_generate_private_params():
    with pytest.warns(None) as warnings_list:
        ed25519_private_params = \
            Ed25519PrivateKeyParams.generate_private_params()
    assert not warnings_list
    assert type(ed25519_private_params) == Ed25519PrivateKeyParams

    with pytest.warns(None) as warnings_list:
        ed25519_private_params.check_params_are_valid()
    assert not warnings_list


def test_ed25519_private_convert_from_unknown():
    with pytest.raises(NotImplementedError):
        Ed25519PrivateKeyParams.convert_from('random')


def test_ed25519_private_convert_from_cryptography_private():
    ed25519_key_object = ed25519.Ed25519PrivateKey.generate()
    converted = Ed25519PrivateKeyParams.convert_from(ed25519_key_object)
    assert type(converted) == Ed25519PrivateKeyParams
    public_bytes = ed25519_key_object.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    assert converted == {
        'public': public_bytes,
        'private_public': ed25519_key_object.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ) + public_bytes
    }


def test_ed25519_private_convert_from_bytes_private():
    ed25519_key_object = secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
    converted = Ed25519PrivateKeyParams.convert_from(ed25519_key_object)
    assert type(converted) == Ed25519PrivateKeyParams
    public_bytes = ed25519.Ed25519PrivateKey.from_private_bytes(
        ed25519_key_object
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    assert converted == {
        'public': public_bytes,
        'private_public': ed25519_key_object + public_bytes
    }


def test_ed25519_private_convert_from_pynacl_private():
    ed25519_key_object = nacl.signing.SigningKey.generate()
    converted = Ed25519PrivateKeyParams.convert_from(ed25519_key_object)
    assert type(converted) == Ed25519PrivateKeyParams
    public_bytes = ed25519_key_object.verify_key
    assert converted == {
        'public': bytes(public_bytes),
        'private_public': bytes(ed25519_key_object) + bytes(public_bytes)
    }


def test_ed25519_private_convert_to_cryptography_private():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(ed25519.Ed25519PrivateKey)
    assert isinstance(converted, ed25519.Ed25519PrivateKey)
    assert converted.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ) == ed25519_private['private_public'][:Ed25519PublicKeyParams.KEY_SIZE]


def test_ed25519_private_convert_to_cryptography_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(ed25519.Ed25519PublicKey)
    assert isinstance(converted, ed25519.Ed25519PublicKey)
    assert converted.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) == ed25519_private['public']


def test_ed25519_private_convert_to_bytes_private():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(bytes)
    assert type(converted) == bytes
    assert converted == \
        ed25519_private['private_public'][:Ed25519PublicKeyParams.KEY_SIZE]


def test_ed25519_private_convert_to_pynacl_private():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(nacl.signing.SigningKey)
    assert type(converted) == nacl.signing.SigningKey
    assert bytes(converted) == \
        ed25519_private['private_public'][:Ed25519PublicKeyParams.KEY_SIZE]


def test_ed25519_private_convert_to_pynacl_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(nacl.signing.VerifyKey)
    assert type(converted) == nacl.signing.VerifyKey
    assert bytes(converted) == ed25519_private['public']


def test_ed25519_private_convert_to_missing_pynacl(mocker):
    mocker.patch.dict(sys.modules, {'nacl': None})
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    with pytest.raises(NotImplementedError):
        ed25519_private.convert_to(nacl.signing.VerifyKey)


def test_ed25519_public_convert_to_not_implemented():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    with pytest.raises(NotImplementedError):
        assert ed25519_private.convert_to(type)
