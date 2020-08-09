import warnings
import secrets
import sys

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ed25519
)
import nacl.public

from openssh_key.key_params import (
    create_public_key_params,
    create_private_key_params,
    RSAPublicKeyParams,
    RSAPrivateKeyParams,
    Ed25519PublicKeyParams,
    Ed25519PrivateKeyParams
)
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction


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
    with pytest.warns(None) as warnings_list:
        rsa_public.check_params_are_valid()
    assert not warnings_list


def test_rsa_public_check_extra_params_are_valid():
    rsa_public = RSAPublicKeyParams({
        'e': 1,
        'n': 2,
        'random': 3
    })
    with pytest.warns(None) as warnings_list:
        rsa_public.check_params_are_valid()
    assert not warnings_list


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
    with pytest.warns(None) as warnings_list:
        rsa_private.check_params_are_valid()
    assert not warnings_list


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
    with pytest.warns(None) as warnings_list:
        rsa_private.check_params_are_valid()
    assert not warnings_list


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


def test_rsa_public_convert_from_unknown():
    with pytest.raises(NotImplementedError):
        RSAPublicKeyParams.convert_from('random')


def test_rsa_public_convert_from_cryptography_public():
    rsa_key_object = rsa.generate_private_key(
        RSAPrivateKeyParams.PUBLIC_EXPONENT,
        RSAPrivateKeyParams.KEY_SIZE,
        default_backend()
    ).public_key()
    rsa_numbers = rsa_key_object.public_numbers()
    converted = RSAPublicKeyParams.convert_from(rsa_key_object)
    assert isinstance(converted, RSAPublicKeyParams)
    assert converted == {
        'e': rsa_numbers.e,
        'n': rsa_numbers.n
    }


def test_rsa_public_convert_cryptography_public():
    rsa_private = RSAPrivateKeyParams.generate_private_params()
    rsa_public = RSAPublicKeyParams({
        'e': rsa_private['e'],
        'n': rsa_private['n']
    })
    converted = rsa_public.convert_to(rsa.RSAPublicKey)
    assert isinstance(converted, rsa.RSAPublicKey)
    assert converted.public_numbers() == rsa.RSAPublicNumbers(
        rsa_public['e'],
        rsa_public['n']
    )


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
    with pytest.warns(None) as warnings_list:
        rsa_private_params = RSAPrivateKeyParams.generate_private_params()
    assert not warnings_list
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
    private_key = private_numbers.private_key(backend=default_backend())
    assert private_key.key_size == RSAPrivateKeyParams.KEY_SIZE


def test_rsa_private_generate_private_params_valid_public_exponent():
    e = 3
    with pytest.warns(None) as warnings_list:
        rsa_private_params = RSAPrivateKeyParams.generate_private_params(e=e)
    assert not warnings_list
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
    private_key = private_numbers.private_key(backend=default_backend())
    assert private_key.key_size == RSAPrivateKeyParams.KEY_SIZE


def test_rsa_private_generate_private_params_invalid_public_exponent():
    e = 1
    with pytest.raises(ValueError):
        RSAPrivateKeyParams.generate_private_params(e=e)


def test_rsa_private_generate_private_params_valid_key_size():
    key_size = 1024
    with pytest.warns(None) as warnings_list:
        rsa_private_params = RSAPrivateKeyParams.generate_private_params(
            key_size=key_size
        )
    assert not warnings_list
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
    private_key = private_numbers.private_key(backend=default_backend())
    assert private_key.key_size == key_size


def test_rsa_private_generate_private_params_invalid_key_size():
    key_size = 1
    with pytest.raises(ValueError):
        RSAPrivateKeyParams.generate_private_params(key_size=key_size)


def test_rsa_private_convert_cryptography_private():
    rsa_private = RSAPrivateKeyParams.generate_private_params()
    converted = rsa_private.convert_to(rsa.RSAPrivateKey)
    assert isinstance(converted, rsa.RSAPrivateKey)
    assert converted.private_numbers() == rsa.RSAPrivateNumbers(
        rsa_private['p'],
        rsa_private['q'],
        rsa_private['d'],
        rsa.rsa_crt_dmp1(rsa_private['d'], rsa_private['p']),
        rsa.rsa_crt_dmp1(rsa_private['d'], rsa_private['q']),
        rsa_private['iqmp'],
        rsa.RSAPublicNumbers(
            rsa_private['e'],
            rsa_private['n']
        )
    )


def test_rsa_private_convert_cryptography_public():
    rsa_private = RSAPrivateKeyParams.generate_private_params()
    converted = rsa_private.convert_to(rsa.RSAPublicKey)
    assert isinstance(converted, rsa.RSAPublicKey)
    assert converted.public_numbers() == rsa.RSAPublicNumbers(
        rsa_private['e'],
        rsa_private['n']
    )


def test_rsa_public_convert_not_implemented():
    rsa_private = RSAPrivateKeyParams.generate_private_params()
    with pytest.raises(NotImplementedError):
        assert rsa_private.convert_to(type)


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


def test_ed25519_public_check_params_are_valid():
    ed25519_public = Ed25519PublicKeyParams({
        'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
    })
    with pytest.warns(None) as warnings_list:
        ed25519_public.check_params_are_valid()
    assert not warnings_list


def test_ed25519_public_check_extra_params_are_valid():
    ed25519_public = Ed25519PublicKeyParams({
        'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE),
        'random': b'\x02'
    })
    with pytest.warns(None) as warnings_list:
        ed25519_public.check_params_are_valid()
    assert not warnings_list


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
    public_bytes = secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
    with pytest.warns(None) as warnings_list:
        Ed25519PrivateKeyParams({
            'public': public_bytes,
            'private_public': secrets.token_bytes(
                Ed25519PublicKeyParams.KEY_SIZE) + public_bytes
        })
    assert not warnings_list


def test_ed25519_private_check_extra_params_are_valid():
    public_bytes = secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
    with pytest.warns(None) as warnings_list:
        Ed25519PrivateKeyParams({
            'public': public_bytes,
            'private_public': secrets.token_bytes(
                Ed25519PublicKeyParams.KEY_SIZE) + public_bytes,
            'random': b'\x03'
        })
    assert not warnings_list


def test_ed25519_private_missing_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ed25519_private = Ed25519PrivateKeyParams({
            'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
        })
    with pytest.warns(UserWarning, match='private_public missing'):
        ed25519_private.check_params_are_valid()


def test_ed25519_private_bad_type_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ed25519_private = Ed25519PrivateKeyParams({
            'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE),
            'private_public': 'bad'
        })
    with pytest.warns(
        UserWarning,
        match='private_public should be of class bytes'
    ):
        ed25519_private.check_params_are_valid()


def test_ed25519_public():
    ed25519_public_dict = {
        'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
    }
    ed25519_public = Ed25519PublicKeyParams(ed25519_public_dict)
    assert ed25519_public.params == ed25519_public_dict


def test_ed25519_public_missing_params():
    with pytest.warns(UserWarning, match='public missing'):
        Ed25519PublicKeyParams({})


def test_ed25519_public_convert_cryptography_public():
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


def test_ed25519_public_convert_bytes_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    ed25519_public = Ed25519PublicKeyParams({
        'public': ed25519_private['public']
    })
    converted = ed25519_public.convert_to(bytes)
    assert isinstance(converted, bytes)
    assert converted == ed25519_public['public']


def test_ed25519_public_convert_pynacl_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    ed25519_public = Ed25519PublicKeyParams({
        'public': ed25519_private['public']
    })
    converted = ed25519_public.convert_to(nacl.public.PublicKey)
    assert isinstance(converted, nacl.public.PublicKey)
    assert bytes(converted) == ed25519_public['public']


def test_ed25519_public_convert_missing_pynacl(mocker):
    mocker.patch.dict(sys.modules, {'nacl': None})
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    ed25519_public = Ed25519PublicKeyParams({
        'public': ed25519_private['public']
    })
    with pytest.raises(NotImplementedError):
        ed25519_public.convert_to(nacl.public.PublicKey)


def test_ed25519_private():
    public_bytes = secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
    ed25519_private_dict = {
        'public': public_bytes,
        'private_public': secrets.token_bytes(
            Ed25519PublicKeyParams.KEY_SIZE
        ) + public_bytes
    }
    ed25519_private = Ed25519PrivateKeyParams(ed25519_private_dict)
    assert ed25519_private.params == ed25519_private_dict


def test_ed25519_private_missing_params():
    with pytest.warns(UserWarning, match='private_public missing'):
        Ed25519PrivateKeyParams({
            'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE)
        })


def test_ed25519_private_bad_type_params():
    with pytest.warns(
        UserWarning,
        match='private_public should be of class bytes'
    ):
        Ed25519PrivateKeyParams({
            'public': secrets.token_bytes(Ed25519PublicKeyParams.KEY_SIZE),
            'private_public': 'bad'
        })


def test_ed25519_private_generate_private_params():
    with pytest.warns(None) as warnings_list:
        ed25519_private_params = \
            Ed25519PrivateKeyParams.generate_private_params()
    assert not warnings_list
    assert isinstance(ed25519_private_params, Ed25519PrivateKeyParams)

    with pytest.warns(None) as warnings_list:
        ed25519_private_params.check_params_are_valid()
    assert not warnings_list


def test_ed25519_private_convert_cryptography_private():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(ed25519.Ed25519PrivateKey)
    assert isinstance(converted, ed25519.Ed25519PrivateKey)
    assert converted.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ) == ed25519_private['private_public'][:Ed25519PublicKeyParams.KEY_SIZE]


def test_ed25519_private_convert_cryptography_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(ed25519.Ed25519PublicKey)
    assert isinstance(converted, ed25519.Ed25519PublicKey)
    assert converted.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) == ed25519_private['public']


def test_ed25519_private_convert_bytes_private():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(bytes)
    assert isinstance(converted, bytes)
    assert converted == \
        ed25519_private['private_public'][:Ed25519PublicKeyParams.KEY_SIZE]


def test_ed25519_private_convert_pynacl_private():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(nacl.public.PrivateKey)
    assert isinstance(converted, nacl.public.PrivateKey)
    assert bytes(converted) == \
        ed25519_private['private_public'][:Ed25519PublicKeyParams.KEY_SIZE]


def test_ed25519_private_convert_pynacl_public():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    converted = ed25519_private.convert_to(nacl.public.PublicKey)
    assert isinstance(converted, nacl.public.PublicKey)
    assert bytes(converted) == ed25519_private['public']


def test_ed25519_private_convert_missing_pynacl(mocker):
    mocker.patch.dict(sys.modules, {'nacl': None})
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    with pytest.raises(NotImplementedError):
        ed25519_private.convert_to(nacl.public.PublicKey)


def test_ed25519_public_convert_not_implemented():
    ed25519_private = Ed25519PrivateKeyParams.generate_private_params()
    with pytest.raises(NotImplementedError):
        assert ed25519_private.convert_to(type)


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
