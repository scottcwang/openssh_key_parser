import secrets
import getpass

import pytest

from openssh_key.key_file import (
    PublicKey,
    PrivateKey,
    PublicPrivateKeyPair,
    PrivateKeyList
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
from openssh_key.kdf import create_kdf
from openssh_key.cipher import create_cipher


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
        PublicKey.header_format_instructions_dict(),
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
        PrivateKey.header_format_instructions_dict(),
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
        PrivateKey.footer_format_instructions_dict(),
        footer
    )
    byte_stream = PascalStyleByteStream(write_byte_stream.getvalue())
    key = PrivateKey(byte_stream)
    assert key.header == header
    assert key.params == params
    assert isinstance(key.params, Ed25519PrivateKeyParams)
    assert key.footer == footer


def test_private_key_list_header_format_instructions_dict():
    assert PrivateKeyList.header_format_instructions_dict() == {
        'auth_magic': '15s',
        'cipher': PascalStyleFormatInstruction.STRING,
        'kdf': PascalStyleFormatInstruction.STRING,
        'kdf_options': PascalStyleFormatInstruction.BYTES,
        'num_keys': '>i'
    }


def test_private_key_list_decipher_bytes_format_instructions_dict():
    assert PrivateKeyList.decipher_bytes_header_format_instructions_dict() == {
        'check_int_1': '>I',
        'check_int_2': '>I'
    }


def test_private_key_list_invalid_auth_magic():
    write_byte_stream = PascalStyleByteStream()
    header = {
        'auth_magic': b'not_openssh_key',
        'cipher': 'none',
        'kdf': 'none',
        'kdf_options': b'',
        'num_keys': 0
    }
    write_byte_stream.write_from_format_instructions_dict(
        PrivateKeyList.header_format_instructions_dict(),
        header
    )
    byte_stream = PascalStyleByteStream(write_byte_stream.getvalue())
    with pytest.raises(ValueError):
        PrivateKeyList.from_byte_stream(byte_stream)


def test_private_key_list_negative_num_keys():
    write_byte_stream = PascalStyleByteStream()
    header = {
        'auth_magic': b'openssh-key-v1\x00',
        'cipher': 'none',
        'kdf': 'none',
        'kdf_options': b'',
        'num_keys': -1
    }
    write_byte_stream.write_from_format_instructions_dict(
        PrivateKeyList.header_format_instructions_dict(),
        header
    )
    byte_stream = PascalStyleByteStream(write_byte_stream.getvalue())
    with pytest.raises(ValueError):
        PrivateKeyList.from_byte_stream(byte_stream)


def test_private_key_list_one_key(mocker):
    write_byte_stream = PascalStyleByteStream()

    kdf_options_write_byte_stream = PascalStyleByteStream()
    kdf_options = {}
    kdf_options_write_byte_stream.write_from_format_instructions_dict(
        create_kdf('none').options_format_instructions_dict(),
        kdf_options
    )
    kdf_options_bytes = kdf_options_write_byte_stream.getvalue()

    header = {
        'auth_magic': b'openssh-key-v1\x00',
        'cipher': 'none',
        'kdf': 'none',
        'kdf_options': kdf_options_bytes,
        'num_keys': 1
    }
    write_byte_stream.write_from_format_instructions_dict(
        PrivateKeyList.header_format_instructions_dict(),
        header
    )

    public_bytes = secrets.token_bytes(ED25519_KEY_SIZE)

    public_key_write_byte_stream = PascalStyleByteStream()
    public_key_header = {
        'key_type': 'ssh-ed25519'
    }
    public_key_write_byte_stream.write_from_format_instructions_dict(
        PublicKey.header_format_instructions_dict(),
        public_key_header
    )
    public_key_params = {
        'public': public_bytes
    }
    public_key_write_byte_stream.write_from_format_instructions_dict(
        Ed25519PublicKeyParams.public_format_instructions_dict(),
        public_key_params
    )
    public_key_bytes = public_key_write_byte_stream.getvalue()
    write_byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.BYTES,
        public_key_bytes
    )
    public_key = PublicKey(PascalStyleByteStream(public_key_bytes))

    private_key_write_byte_stream = PascalStyleByteStream()
    private_key_header = {
        'key_type': 'ssh-ed25519'
    }
    private_key_write_byte_stream.write_from_format_instructions_dict(
        PrivateKey.header_format_instructions_dict(),
        private_key_header
    )
    private_key_params = {
        'public': public_bytes,
        'private_public': secrets.token_bytes(ED25519_KEY_SIZE) + public_bytes
    }
    private_key_write_byte_stream.write_from_format_instructions_dict(
        Ed25519PrivateKeyParams.private_format_instructions_dict(),
        private_key_params
    )
    private_key_footer = {
        'comment': 'comment'
    }
    private_key_write_byte_stream.write_from_format_instructions_dict(
        PrivateKey.footer_format_instructions_dict(),
        private_key_footer
    )
    private_key_bytes = private_key_write_byte_stream.getvalue()
    private_key = PrivateKey(PascalStyleByteStream(private_key_bytes))

    decipher_byte_stream = PascalStyleByteStream()
    check_int = secrets.randbits(32)
    decipher_bytes_header = {
        'check_int_1': check_int,
        'check_int_2': check_int
    }
    decipher_byte_stream.write_from_format_instructions_dict(
        PrivateKeyList.decipher_bytes_header_format_instructions_dict(),
        decipher_bytes_header
    )
    # TODO Add correct padding
    decipher_byte_stream.write(private_key_bytes)

    passphrase = 'passphrase'

    kdf_result = create_kdf('none').derive_key(kdf_options, passphrase)

    cipher_bytes = create_cipher('none').encrypt(
        kdf_result['cipher_key'],
        kdf_result['initialization_vector'],
        decipher_byte_stream.getvalue()
    )

    write_byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.BYTES,
        cipher_bytes
    )

    byte_stream = PascalStyleByteStream(write_byte_stream.getvalue())

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    private_key_list = PrivateKeyList.from_byte_stream(byte_stream)

    getpass.getpass.assert_called_once()

    assert private_key_list.bytes == byte_stream.getvalue()
    assert private_key_list.header == header
    assert private_key_list.cipher_bytes == cipher_bytes

    assert private_key_list[0].public.header == public_key.header
    assert private_key_list[0].public.params == public_key.params
    assert private_key_list[0].public.footer == public_key.footer

    assert private_key_list[0].private.header == private_key.header
    assert private_key_list[0].private.params == private_key.params
    assert private_key_list[0].private.footer == private_key.footer

    assert private_key_list.kdf_options == kdf_options

    assert private_key_list.decipher_bytes == decipher_byte_stream.getvalue()
    assert private_key_list.decipher_bytes_header == decipher_bytes_header

    assert private_key_list.decipher_padding == b''
