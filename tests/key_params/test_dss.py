import pytest
import warnings

from cryptography.hazmat.primitives.asymmetric import dsa

from openssh_key.key_params import (
    DSSPrivateKeyParams,
    DSSPublicKeyParams
)
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction


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
