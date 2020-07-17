import secrets

import pytest

from openssh_key.key_file import (
    PublicKey,
    PrivateKey,
)
from openssh_key.pascal_style_byte_stream import (
    PascalStyleByteStream,
    PascalStyleFormatInstruction
)
from openssh_key.key_params import (
    Ed25519PublicKeyParams,
    Ed25519PrivateKeyParams,
    ED25519_KEY_SIZE
)


def test_public_key_header_format_instructions_dict():
    assert PublicKey.header_format_instructions_dict() == {
        'key_type': PascalStyleFormatInstruction.STRING
    }


def test_public_key_footer_format_instructions_dict():
    assert PublicKey.footer_format_instructions_dict() == {}


def test_private_key_header_format_instructions_dict():
    assert PrivateKey.header_format_instructions_dict() == {
        'key_type': PascalStyleFormatInstruction.STRING
    }


def test_private_key_footer_format_instructions_dict():
    assert PrivateKey.footer_format_instructions_dict() == {
        'comment': PascalStyleFormatInstruction.STRING
    }


def test_public_key():
    write_byte_stream = PascalStyleByteStream()
    header = {
        'key_type': 'ssh-ed25519'
    }
    write_byte_stream.write_from_format_instructions_dict(
        {
            'key_type': PascalStyleFormatInstruction.STRING
        },
        header
    )
    params = {
        'public': secrets.token_bytes(ED25519_KEY_SIZE)
    }
    write_byte_stream.write_from_format_instructions_dict(
        Ed25519PublicKeyParams.public_format_instructions_dict(),
        params
    )
    byte_stream = PascalStyleByteStream(write_byte_stream.getvalue())
    key = PublicKey(byte_stream)
    assert key.bytes == byte_stream.getvalue()
    assert key.header == header
    assert isinstance(key.params, Ed25519PublicKeyParams)
    assert key.params == params
    assert key.footer == {}


def test_private_key():
    write_byte_stream = PascalStyleByteStream()
    header = {
        'key_type': 'ssh-ed25519'
    }
    write_byte_stream.write_from_format_instructions_dict(
        {
            'key_type': PascalStyleFormatInstruction.STRING
        },
        header
    )
    public_bytes = secrets.token_bytes(ED25519_KEY_SIZE)
    params = {
        'public': public_bytes,
        'private_public': secrets.token_bytes(ED25519_KEY_SIZE) + public_bytes
    }
    write_byte_stream.write_from_format_instructions_dict(
        Ed25519PrivateKeyParams.private_format_instructions_dict(),
        params
    )
    footer = {
        'comment': 'comment'
    }
    write_byte_stream.write_from_format_instructions_dict(
        {
            'comment': PascalStyleFormatInstruction.STRING
        },
        footer
    )
    byte_stream = PascalStyleByteStream(write_byte_stream.getvalue())
    key = PrivateKey(byte_stream)
    assert key.bytes == byte_stream.getvalue()
    assert key.header == header
    assert key.params == params
    assert isinstance(key.params, Ed25519PrivateKeyParams)
    assert key.footer == footer
