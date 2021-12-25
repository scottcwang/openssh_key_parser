import warnings
import secrets
import sys

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ed25519,
    dsa
)
import nacl.signing

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
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction


def test_factory_rsa_public():
    assert create_public_key_params('ssh-rsa') == RSAPublicKeyParams


def test_factory_rsa_private():
    assert create_private_key_params('ssh-rsa') == RSAPrivateKeyParams


def test_rsa_public_format_instructions_dict():
    assert RSAPublicKeyParams.FORMAT_INSTRUCTIONS_DICT == {
        'e': PascalStyleFormatInstruction.MPINT,
        'n': PascalStyleFormatInstruction.MPINT,
    }


def test_rsa_private_format_instructions_dict():
    assert RSAPrivateKeyParams.FORMAT_INSTRUCTIONS_DICT == {
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
    assert type(converted) == RSAPublicKeyParams
    assert converted == {
        'e': rsa_numbers.e,
        'n': rsa_numbers.n
    }


def test_rsa_public_convert_from_cryptography_private():
    rsa_key_object = rsa.generate_private_key(
        RSAPrivateKeyParams.PUBLIC_EXPONENT,
        RSAPrivateKeyParams.KEY_SIZE,
        default_backend()
    )
    rsa_numbers = rsa_key_object.private_numbers()
    converted = RSAPublicKeyParams.convert_from(rsa_key_object)
    assert type(converted) == RSAPublicKeyParams
    assert converted == {
        'e': rsa_numbers.public_numbers.e,
        'n': rsa_numbers.public_numbers.n
    }


def test_rsa_public_convert_to_cryptography_public():
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
    assert type(rsa_private_params) == RSAPrivateKeyParams

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
    assert type(rsa_private_params) == RSAPrivateKeyParams

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
    assert type(rsa_private_params) == RSAPrivateKeyParams

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


def test_rsa_private_convert_from_unknown():
    with pytest.raises(NotImplementedError):
        RSAPrivateKeyParams.convert_from('random')


def test_rsa_private_convert_from_cryptography_private():
    rsa_key_object = rsa.generate_private_key(
        RSAPrivateKeyParams.PUBLIC_EXPONENT,
        RSAPrivateKeyParams.KEY_SIZE,
        default_backend()
    )
    rsa_numbers = rsa_key_object.private_numbers()
    converted = RSAPrivateKeyParams.convert_from(rsa_key_object)
    assert type(converted) == RSAPrivateKeyParams
    assert converted == {
        'n': rsa_numbers.public_numbers.n,
        'e': rsa_numbers.public_numbers.e,
        'd': rsa_numbers.d,
        'iqmp': rsa_numbers.iqmp,
        'p': rsa_numbers.p,
        'q': rsa_numbers.q
    }


def test_rsa_private_convert_to_cryptography_private():
    rsa_private = RSAPrivateKeyParams.generate_private_params()
    converted = rsa_private.convert_to(rsa.RSAPrivateKeyWithSerialization)
    assert isinstance(converted, rsa.RSAPrivateKeyWithSerialization)
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

def test_rsa_private_convert_to_cryptography_rsaprivatekey():
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


def test_rsa_private_convert_to_cryptography_public():
    rsa_private = RSAPrivateKeyParams.generate_private_params()
    converted = rsa_private.convert_to(rsa.RSAPublicKey)
    assert isinstance(converted, rsa.RSAPublicKey)
    assert converted.public_numbers() == rsa.RSAPublicNumbers(
        rsa_private['e'],
        rsa_private['n']
    )


def test_rsa_public_convert_to_not_implemented():
    rsa_private = RSAPrivateKeyParams.generate_private_params()
    with pytest.raises(NotImplementedError):
        assert rsa_private.convert_to(type)


def test_factory_ed25519_public():
    assert create_public_key_params('ssh-ed25519') == Ed25519PublicKeyParams


def test_factory_ed25519_private():
    assert create_private_key_params('ssh-ed25519') == Ed25519PrivateKeyParams


def test_ed25519_public_format_instructions_dict():
    assert Ed25519PublicKeyParams.FORMAT_INSTRUCTIONS_DICT == {
        'public': PascalStyleFormatInstruction.BYTES
    }


def test_ed25519_private_format_instructions_dict():
    assert Ed25519PrivateKeyParams.FORMAT_INSTRUCTIONS_DICT == {
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


def test_factory_dss_public():
    assert create_public_key_params('ssh-dss') == DSSPublicKeyParams


def test_factory_dss_private():
    assert create_private_key_params('ssh-dss') == DSSPrivateKeyParams


def test_dss_public_format_instructions_dict():
    assert DSSPublicKeyParams.FORMAT_INSTRUCTIONS_DICT == {
        'p': PascalStyleFormatInstruction.MPINT,
        'q': PascalStyleFormatInstruction.MPINT,
        'g': PascalStyleFormatInstruction.MPINT,
        'y': PascalStyleFormatInstruction.MPINT,
    }


def test_dss_private_format_instructions_dict():
    assert DSSPrivateKeyParams.FORMAT_INSTRUCTIONS_DICT == {
        'p': PascalStyleFormatInstruction.MPINT,
        'q': PascalStyleFormatInstruction.MPINT,
        'g': PascalStyleFormatInstruction.MPINT,
        'y': PascalStyleFormatInstruction.MPINT,
        'x': PascalStyleFormatInstruction.MPINT,
    }


def test_dss_public_check_params_are_valid():
    dss_public = DSSPublicKeyParams({
        'p': 1,
        'q': 2,
        'g': 3,
        'y': 4,
    })
    with pytest.warns(None) as warnings_list:
        dss_public.check_params_are_valid()
    assert not warnings_list


def test_dss_public_check_extra_params_are_valid():
    dss_public = DSSPublicKeyParams({
        'p': 1,
        'q': 2,
        'g': 3,
        'y': 4,
        'random': 5
    })
    with pytest.warns(None) as warnings_list:
        dss_public.check_params_are_valid()
    assert not warnings_list


def test_dss_public_missing_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        dss_public = DSSPublicKeyParams({
            'p': 1,
            'q': 2,
            'g': 3,
        })
    with pytest.warns(UserWarning, match='y missing'):
        dss_public.check_params_are_valid()


def test_dss_public_bad_type_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        dss_public = DSSPublicKeyParams({
            'p': 1,
            'q': 2,
            'g': 3,
            'y': b'bad',
        })
    with pytest.warns(UserWarning, match='y should be of class int'):
        dss_public.check_params_are_valid()


def test_dss_private_check_params_are_valid():
    dss_private = DSSPrivateKeyParams({
        'p': 1,
        'q': 2,
        'g': 3,
        'y': 4,
        'x': 5,
    })
    with pytest.warns(None) as warnings_list:
        dss_private.check_params_are_valid()
    assert not warnings_list


def test_dss_private_check_extra_params_are_valid():
    dss_private = DSSPrivateKeyParams({
        'p': 1,
        'q': 2,
        'g': 3,
        'y': 4,
        'x': 5,
        'random': 6
    })
    with pytest.warns(None) as warnings_list:
        dss_private.check_params_are_valid()
    assert not warnings_list


def test_dss_private_missing_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        dss_private = DSSPrivateKeyParams({
            'p': 1,
            'q': 2,
            'g': 3,
            'y': 4,
        })
    with pytest.warns(UserWarning, match='x missing'):
        dss_private.check_params_are_valid()


def test_dss_private_bad_type_params_are_not_valid():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        dss_private = DSSPrivateKeyParams({
            'p': 1,
            'q': 2,
            'g': 3,
            'y': 4,
            'x': b'bad'
        })
    with pytest.warns(UserWarning, match='x should be of class int'):
        dss_private.check_params_are_valid()


def test_dss_public():
    dss_public_dict = {
        'p': 1,
        'q': 2,
        'g': 3,
        'y': 4,
    }
    dss_public = DSSPublicKeyParams(dss_public_dict)
    assert dss_public.params == dss_public_dict


def test_dss_public_missing_params():
    with pytest.warns(UserWarning, match='y missing'):
        DSSPublicKeyParams({
            'p': 1,
            'q': 2,
            'g': 3,
        })


def test_dss_public_convert_from_unknown():
    with pytest.raises(NotImplementedError):
        DSSPublicKeyParams.convert_from('random')


def test_dss_public_convert_from_cryptography_public():
    private_key = dsa.generate_private_key(
        DSSPrivateKeyParams.KEY_SIZE
    ).public_key()
    public_numbers = private_key.public_numbers()
    parameter_numbers = public_numbers.parameter_numbers
    converted = DSSPublicKeyParams.convert_from(private_key)
    assert type(converted) == DSSPublicKeyParams
    assert converted == {
        'p': parameter_numbers.p,
        'q': parameter_numbers.q,
        'g': parameter_numbers.g,
        'y': public_numbers.y,
    }


def test_dss_public_convert_from_cryptography_private():
    private_key = dsa.generate_private_key(
        DSSPrivateKeyParams.KEY_SIZE
    )
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    parameter_numbers = public_numbers.parameter_numbers
    converted = DSSPublicKeyParams.convert_from(private_key)
    assert type(converted) == DSSPublicKeyParams
    assert converted == {
        'p': parameter_numbers.p,
        'q': parameter_numbers.q,
        'g': parameter_numbers.g,
        'y': public_numbers.y,
    }


def test_dss_public_convert_to_cryptography_public():
    dss_private = DSSPrivateKeyParams.generate_private_params()
    dss_public = DSSPublicKeyParams({
        'p': dss_private['p'],
        'q': dss_private['q'],
        'g': dss_private['g'],
        'y': dss_private['y'],
    })
    converted = dss_public.convert_to(dsa.DSAPublicKey)
    assert isinstance(converted, dsa.DSAPublicKey)
    assert converted.public_numbers() == dsa.DSAPublicNumbers(
        dss_public['y'],
        dsa.DSAParameterNumbers(
            dss_public['p'],
            dss_public['q'],
            dss_public['g']
        )
    )


def test_dss_private():
    dss_private_dict = {
        'p': 1,
        'q': 2,
        'g': 3,
        'y': 4,
        'x': 5,
    }
    dss_private = DSSPrivateKeyParams(dss_private_dict)
    assert dss_private.params == dss_private_dict


def test_dss_private_missing_params():
    with pytest.warns(UserWarning, match='x missing'):
        DSSPrivateKeyParams({
            'p': 1,
            'q': 2,
            'g': 3,
            'y': 4,
        })


def test_dss_private_bad_type_params():
    with pytest.warns(UserWarning, match='x should be of class int'):
        DSSPrivateKeyParams({
            'p': 1,
            'q': 2,
            'g': 3,
            'y': 4,
            'x': b'bad'
        })


def test_dss_private_convert_from_unknown():
    with pytest.raises(NotImplementedError):
        DSSPrivateKeyParams.convert_from('random')


def test_dss_private_convert_from_cryptography_private():
    private_key = dsa.generate_private_key(
        DSSPrivateKeyParams.KEY_SIZE
    )
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    parameter_numbers = public_numbers.parameter_numbers
    converted = DSSPrivateKeyParams.convert_from(private_key)
    assert type(converted) == DSSPrivateKeyParams
    assert converted == {
        'p': parameter_numbers.p,
        'q': parameter_numbers.q,
        'g': parameter_numbers.g,
        'y': public_numbers.y,
        'x': private_numbers.x,
    }


def test_dss_private_convert_to_cryptography_private():
    dss_private = DSSPrivateKeyParams.generate_private_params()
    converted = dss_private.convert_to(dsa.DSAPrivateKeyWithSerialization)
    assert isinstance(converted, dsa.DSAPrivateKeyWithSerialization)
    assert converted.private_numbers() == dsa.DSAPrivateNumbers(
        dss_private['x'],
        dsa.DSAPublicNumbers(
            dss_private['y'],
            dsa.DSAParameterNumbers(
                dss_private['p'],
                dss_private['q'],
                dss_private['g']
            )
        )
    )


def test_dss_private_convert_to_cryptography_dssprivatekey():
    dss_private = DSSPrivateKeyParams.generate_private_params()
    converted = dss_private.convert_to(dsa.DSAPrivateKey)
    assert isinstance(converted, dsa.DSAPrivateKey)
    assert converted.private_numbers() == dsa.DSAPrivateNumbers(
        dss_private['x'],
        dsa.DSAPublicNumbers(
            dss_private['y'],
            dsa.DSAParameterNumbers(
                dss_private['p'],
                dss_private['q'],
                dss_private['g']
            )
        )
    )


def test_dss_private_convert_to_cryptography_public():
    dss_private = DSSPrivateKeyParams.generate_private_params()
    converted = dss_private.convert_to(dsa.DSAPublicKey)
    assert isinstance(converted, dsa.DSAPublicKey)
    assert converted.public_numbers() == dsa.DSAPublicNumbers(
        dss_private['y'],
        dsa.DSAParameterNumbers(
            dss_private['p'],
            dss_private['q'],
            dss_private['g']
        )
    )


def test_dss_public_convert_to_not_implemented():
    dss_private = DSSPrivateKeyParams.generate_private_params()
    with pytest.raises(NotImplementedError):
        assert dss_private.convert_to(type)


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
