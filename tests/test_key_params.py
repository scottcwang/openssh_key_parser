import warnings
import secrets

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from openssh_key.key_params import (
    create_public_key_params,
    create_private_key_params,
    RSAPublicKeyParams,
    RSAPrivateKeyParams,
    Ed25519PublicKeyParams,
    Ed25519PrivateKeyParams
)
from openssh_key.pascal_style_byte_stream import (
    PascalStyleFormatInstruction,
    PascalStyleByteStream
)


def test_factory_rsa_public():
    assert isinstance(
        create_public_key_params('ssh-rsa'),
        RSAPublicKeyParams.__class__
    )


def test_factory_rsa_private():
    assert isinstance(
        create_private_key_params('ssh-rsa'),
        RSAPrivateKeyParams.__class__
    )


def test_rsa_public_format_instructions_dict():
    assert RSAPublicKeyParams.public_format_instructions_dict() == {
        'e': PascalStyleFormatInstruction.MPINT,
        'n': PascalStyleFormatInstruction.MPINT,
    }


def test_rsa_private_format_instructions_dict():
    assert RSAPrivateKeyParams.private_format_instructions_dict() == {
        'n': PascalStyleFormatInstruction.MPINT,
        'e': PascalStyleFormatInstruction.MPINT,
        'd': PascalStyleFormatInstruction.MPINT,
        'iqmp': PascalStyleFormatInstruction.MPINT,
        'p': PascalStyleFormatInstruction.MPINT,
        'q': PascalStyleFormatInstruction.MPINT,
    }


def test_rsa_public_check_params_are_valid():
    rsa_public = RSAPublicKeyParams({
        'e': 1,
        'n': 2
    })
    with pytest.warns(None) as warnings:
        rsa_public.check_params_are_valid()
    assert not warnings


def test_rsa_public_check_extra_params_are_valid():
    rsa_public = RSAPublicKeyParams({
        'e': 1,
        'n': 2,
        'random': 3
    })
    with pytest.warns(None) as warnings:
        rsa_public.check_params_are_valid()
    assert not warnings


def test_rsa_public_missing_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rsa_public = RSAPublicKeyParams({
            'e': 1
        })
    with pytest.warns(UserWarning, match='n missing'):
        rsa_public.check_params_are_valid()


def test_rsa_public_bad_type_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rsa_public = RSAPublicKeyParams({
            'e': 1,
            'n': b'bad'
        })
    with pytest.warns(UserWarning, match='n should be of class int'):
        rsa_public.check_params_are_valid()


def test_rsa_private_check_params_are_valid():
    rsa_private = RSAPrivateKeyParams({
        'n': 1,
        'e': 2,
        'd': 3,
        'iqmp': 4,
        'p': 5,
        'q': 6
    })
    with pytest.warns(None) as warnings:
        rsa_private.check_params_are_valid()
    assert not warnings


def test_rsa_private_check_extra_params_are_valid():
    rsa_private = RSAPrivateKeyParams({
        'n': 1,
        'e': 2,
        'd': 3,
        'iqmp': 4,
        'p': 5,
        'q': 6,
        'random': 7
    })
    with pytest.warns(None) as warnings:
        rsa_private.check_params_are_valid()
    assert not warnings


def test_rsa_private_missing_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rsa_private = RSAPrivateKeyParams({
            'n': 1,
            'e': 2,
            'd': 3,
            'iqmp': 4,
            'p': 5
        })
    with pytest.warns(UserWarning, match='q missing'):
        rsa_private.check_params_are_valid()


def test_rsa_private_bad_type_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rsa_private = RSAPrivateKeyParams({
            'n': 1,
            'e': 2,
            'd': 3,
            'iqmp': 4,
            'p': 5,
            'q': b'bad'
        })
    with pytest.warns(UserWarning, match='q should be of class int'):
        rsa_private.check_params_are_valid()


def test_rsa_public():
    rsa_public_dict = {
        'e': 1,
        'n': 2
    }
    rsa_public = RSAPublicKeyParams(rsa_public_dict)
    assert rsa_public.params == rsa_public_dict


def test_rsa_public_missing_params():
    with pytest.warns(UserWarning, match='n missing'):
        RSAPublicKeyParams({
            'e': 1
        })


def test_rsa_private():
    rsa_private_dict = {
        'n': 1,
        'e': 2,
        'd': 3,
        'iqmp': 4,
        'p': 5,
        'q': 6
    }
    rsa_private = RSAPrivateKeyParams(rsa_private_dict)
    assert rsa_private.params == rsa_private_dict


def test_rsa_private_missing_params():
    with pytest.warns(UserWarning, match='q missing'):
        RSAPrivateKeyParams({
            'n': 1,
            'e': 2,
            'd': 3,
            'iqmp': 4,
            'p': 5
        })


def test_rsa_private_bad_type_params():
    with pytest.warns(UserWarning, match='q should be of class int'):
        RSAPrivateKeyParams({
            'n': 1,
            'e': 2,
            'd': 3,
            'iqmp': 4,
            'p': 5,
            'q': b'bad'
        })


def test_rsa_private_generate_private_params():
    with pytest.warns(None) as warnings:
        rsa_private_params = RSAPrivateKeyParams.generate_private_params()
    assert not warnings
    assert isinstance(rsa_private_params, RSAPrivateKeyParams)

    private_numbers = rsa.RSAPrivateNumbers(
        rsa_private_params['p'],
        rsa_private_params['q'],
        rsa_private_params['d'],
        rsa.rsa_crt_dmp1(rsa_private_params['d'], rsa_private_params['p']),
        rsa.rsa_crt_dmp1(rsa_private_params['d'], rsa_private_params['q']),
        rsa_private_params['iqmp'],
        rsa.RSAPublicNumbers(
            RSAPrivateKeyParams.PUBLIC_EXPONENT,
            rsa_private_params['n']
        )
    )
    try:
        private_key = private_numbers.private_key(backend=default_backend())
    except Exception as e:
        pytest.fail(e)

    assert private_key.key_size == RSAPrivateKeyParams.KEY_SIZE


def test_rsa_private_generate_private_params_valid_public_exponent():
    e = 3
    with pytest.warns(None) as warnings:
        rsa_private_params = RSAPrivateKeyParams.generate_private_params(e=e)
    assert not warnings
    assert isinstance(rsa_private_params, RSAPrivateKeyParams)

    private_numbers = rsa.RSAPrivateNumbers(
        rsa_private_params['p'],
        rsa_private_params['q'],
        rsa_private_params['d'],
        rsa.rsa_crt_dmp1(rsa_private_params['d'], rsa_private_params['p']),
        rsa.rsa_crt_dmp1(rsa_private_params['d'], rsa_private_params['q']),
        rsa_private_params['iqmp'],
        rsa.RSAPublicNumbers(
            e,
            rsa_private_params['n']
        )
    )
    try:
        private_key = private_numbers.private_key(backend=default_backend())
    except Exception as e:
        pytest.fail(e)
    assert private_key.key_size == RSAPrivateKeyParams.KEY_SIZE


def test_rsa_private_generate_private_params_invalid_public_exponent():
    e = 1
    with pytest.raises(ValueError):
        RSAPrivateKeyParams.generate_private_params(e=e)


def test_rsa_private_generate_private_params_valid_key_size():
    key_size = 1024
    with pytest.warns(None) as warnings:
        rsa_private_params = RSAPrivateKeyParams.generate_private_params(
            key_size=key_size
        )
    assert not warnings
    assert isinstance(rsa_private_params, RSAPrivateKeyParams)

    private_numbers = rsa.RSAPrivateNumbers(
        rsa_private_params['p'],
        rsa_private_params['q'],
        rsa_private_params['d'],
        rsa.rsa_crt_dmp1(rsa_private_params['d'], rsa_private_params['p']),
        rsa.rsa_crt_dmp1(rsa_private_params['d'], rsa_private_params['q']),
        rsa_private_params['iqmp'],
        rsa.RSAPublicNumbers(
            RSAPrivateKeyParams.PUBLIC_EXPONENT,
            rsa_private_params['n']
        )
    )
    try:
        private_key = private_numbers.private_key(backend=default_backend())
    except Exception as e:
        pytest.fail(e)
    assert private_key.key_size == key_size


def test_rsa_private_generate_private_params_invalid_key_size():
    key_size = 1
    with pytest.raises(ValueError):
        RSAPrivateKeyParams.generate_private_params(key_size=key_size)


def test_factory_ed25519_public():
    assert isinstance(
        create_public_key_params('ssh-ed25519'),
        Ed25519PublicKeyParams.__class__
    )


def test_factory_ed25519_private():
    assert isinstance(
        create_private_key_params('ssh-ed25519'),
        Ed25519PrivateKeyParams.__class__
    )


def test_ed25519_public_format_instructions_dict():
    assert Ed25519PublicKeyParams.public_format_instructions_dict() == {
        'public': PascalStyleFormatInstruction.BYTES
    }


def test_ed25519_private_format_instructions_dict():
    assert Ed25519PrivateKeyParams.private_format_instructions_dict() == {
        'public': PascalStyleFormatInstruction.BYTES,
        'private_public': PascalStyleFormatInstruction.BYTES
    }


ED25519_KEY_SIZE = 32


def test_ed25519_public_check_params_are_valid():
    ed25519_public = Ed25519PublicKeyParams({
        'public': secrets.token_bytes(ED25519_KEY_SIZE)
    })
    with pytest.warns(None) as warnings:
        ed25519_public.check_params_are_valid()
    assert not warnings


def test_ed25519_public_check_extra_params_are_valid():
    ed25519_public = Ed25519PublicKeyParams({
        'public': secrets.token_bytes(ED25519_KEY_SIZE),
        'random': b'\x02'
    })
    with pytest.warns(None) as warnings:
        ed25519_public.check_params_are_valid()
    assert not warnings


def test_ed25519_public_missing_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ed25519_public = Ed25519PublicKeyParams({})
    with pytest.warns(UserWarning, match='public missing'):
        ed25519_public.check_params_are_valid()


def test_ed25519_public_bad_type_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ed25519_public = Ed25519PublicKeyParams({
            'public': 'bad'
        })
    with pytest.warns(UserWarning, match='public should be of class bytes'):
        ed25519_public.check_params_are_valid()


def test_ed25519_private_check_params_are_valid():
    public_bytes = secrets.token_bytes(ED25519_KEY_SIZE)
    with pytest.warns(None) as warnings:
        Ed25519PrivateKeyParams({
            'public': public_bytes,
            'private_public': secrets.token_bytes(
                ED25519_KEY_SIZE) + public_bytes
        })
    assert not warnings


def test_ed25519_private_check_extra_params_are_valid():
    public_bytes = secrets.token_bytes(ED25519_KEY_SIZE)
    with pytest.warns(None) as warnings:
        Ed25519PrivateKeyParams({
            'public': public_bytes,
            'private_public': secrets.token_bytes(
                ED25519_KEY_SIZE) + public_bytes,
            'random': b'\x03'
        })
    assert not warnings


def test_ed25519_private_missing_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ed25519_private = Ed25519PrivateKeyParams({
            'public': secrets.token_bytes(ED25519_KEY_SIZE)
        })
    with pytest.warns(UserWarning, match='private_public missing'):
        ed25519_private.check_params_are_valid()


def test_ed25519_private_bad_type_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ed25519_private = Ed25519PrivateKeyParams({
            'public': secrets.token_bytes(ED25519_KEY_SIZE),
            'private_public': 'bad'
        })
    with pytest.warns(
        UserWarning,
        match='private_public should be of class bytes'
    ):
        ed25519_private.check_params_are_valid()


def test_ed25519_public():
    ed25519_public_dict = {
        'public': secrets.token_bytes(ED25519_KEY_SIZE)
    }
    ed25519_public = Ed25519PublicKeyParams(ed25519_public_dict)
    assert ed25519_public.params == ed25519_public_dict


def test_ed25519_public_missing_params():
    with pytest.warns(UserWarning, match='public missing'):
        Ed25519PublicKeyParams({})


def test_ed25519_private():
    public_bytes = secrets.token_bytes(ED25519_KEY_SIZE)
    ed25519_private_dict = {
        'public': public_bytes,
        'private_public': secrets.token_bytes(ED25519_KEY_SIZE) + public_bytes
    }
    ed25519_private = Ed25519PrivateKeyParams(ed25519_private_dict)
    assert ed25519_private.params == ed25519_private_dict


def test_ed25519_private_missing_params():
    with pytest.warns(UserWarning, match='private_public missing'):
        Ed25519PrivateKeyParams({
            'public': secrets.token_bytes(ED25519_KEY_SIZE)
        })


def test_ed25519_private_bad_type_params():
    with pytest.warns(
        UserWarning,
        match='private_public should be of class bytes'
    ):
        Ed25519PrivateKeyParams({
            'public': secrets.token_bytes(ED25519_KEY_SIZE),
            'private_public': 'bad'
        })


def test_str():
    public_bytes = secrets.token_bytes(ED25519_KEY_SIZE)
    ed25519_private_dict = {
        'public': public_bytes,
        'private_public': secrets.token_bytes(ED25519_KEY_SIZE) + public_bytes
    }
    ed25519_private = Ed25519PrivateKeyParams(ed25519_private_dict)
    assert str(ed25519_private) == str(ed25519_private_dict)
