import pytest
import warnings

from cryptography.hazmat.primitives.asymmetric import rsa

from openssh_key.key_params import (
    RSAPrivateKeyParams,
    RSAPublicKeyParams
)
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction


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
        RSAPrivateKeyParams.KEY_SIZE
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
        RSAPrivateKeyParams.KEY_SIZE
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
    private_key = private_numbers.private_key()
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
    private_key = private_numbers.private_key()
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
    private_key = private_numbers.private_key()
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
        RSAPrivateKeyParams.KEY_SIZE
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
