import pytest

from openssh_key.key_params import create_key_params, RSAPublicKeyParams, RSAPrivateKeyParams
from openssh_key.pascal_style_byte_stream import PascalStyleFormatInstruction, PascalStyleByteStream


def test_factory_rsa_public():
    assert isinstance(create_key_params(
        'ssh-rsa', 'public'), RSAPublicKeyParams.__class__)


def test_factory_rsa_private():
    assert isinstance(create_key_params(
        'ssh-rsa', 'private'), RSAPrivateKeyParams.__class__)


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


def test_rsa_public_params_are_valid():
    rsa_public_dict = {
        'e': 1,
        'n': 2
    }
    rsa_public_comment = 'comment'
    rsa_public = RSAPublicKeyParams(rsa_public_dict, rsa_public_comment)
    assert rsa_public.params_are_valid()


def test_rsa_public_extra_params_are_valid():
    rsa_public_dict = {
        'e': 1,
        'n': 2,
        'random': 3
    }
    rsa_public_comment = 'comment'
    rsa_public = RSAPublicKeyParams(rsa_public_dict, rsa_public_comment)
    assert rsa_public.params_are_valid()


def test_rsa_public_missing_params_are_not_valid():
    rsa_public_dict = {
        'e': 1
    }
    rsa_public_comment = 'comment'
    rsa_public = RSAPublicKeyParams(rsa_public_dict, rsa_public_comment)
    assert not rsa_public.params_are_valid()


def test_rsa_private_params_are_valid():
    rsa_private_dict = {
        'n': 1,
        'e': 2,
        'd': 3,
        'iqmp': 4,
        'p': 5,
        'q': 6
    }
    rsa_private_comment = 'comment'
    rsa_private = RSAPrivateKeyParams(rsa_private_dict, rsa_private_comment)
    assert rsa_private.params_are_valid()


def test_rsa_private_extra_params_are_valid():
    rsa_private_dict = {
        'n': 1,
        'e': 2,
        'd': 3,
        'iqmp': 4,
        'p': 5,
        'q': 6,
        'random': 7
    }
    rsa_private_comment = 'comment'
    rsa_private = RSAPrivateKeyParams(rsa_private_dict, rsa_private_comment)
    assert rsa_private.params_are_valid()


def test_rsa_private_missing_params_are_not_valid():
    rsa_private_dict = {
        'n': 1,
        'e': 2,
        'd': 3,
        'iqmp': 4,
        'p': 5
    }
    rsa_private_comment = 'comment'
    rsa_private = RSAPrivateKeyParams(rsa_private_dict, rsa_private_comment)
    assert not rsa_private.params_are_valid()


def test_rsa_public():
    rsa_public_dict = {
        'e': 1,
        'n': 2
    }
    rsa_public_comment = 'comment'
    rsa_public = RSAPublicKeyParams(rsa_public_dict, rsa_public_comment)
    assert rsa_public.params == rsa_public_dict and rsa_public.comment == rsa_public_comment


def test_rsa_public_missing_params():
    rsa_public_dict = {
        'e': 1
    }
    rsa_public_comment = 'comment'
    with pytest.warns(UserWarning):
        RSAPublicKeyParams(rsa_public_dict, rsa_public_comment)


def test_rsa_private():
    rsa_private_dict = {
        'n': 1,
        'e': 2,
        'd': 3,
        'iqmp': 4,
        'p': 5,
        'q': 6
    }
    rsa_private_comment = 'comment'
    rsa_private = RSAPrivateKeyParams(rsa_private_dict, rsa_private_comment)
    assert rsa_private.params == rsa_private_dict and rsa_private.comment == rsa_private_comment


def test_rsa_private_missing_params():
    rsa_private_dict = {
        'n': 1,
        'e': 2,
        'd': 3,
        'iqmp': 4,
        'p': 5
    }
    rsa_private_comment = 'comment'
    with pytest.warns(UserWarning):
        RSAPrivateKeyParams(rsa_private_dict, rsa_private_comment)
