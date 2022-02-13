import base64
import getpass
import secrets
import warnings

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from openssh_key.cipher import ConfidentialityIntegrityCipher, get_cipher_class
from openssh_key.kdf_options import get_kdf_options_class
from openssh_key.key import PrivateKey, PublicKey
from openssh_key.key_params import (Ed25519PublicKeyParams,
                                    RSAPrivateKeyParams, RSAPublicKeyParams,
                                    get_private_key_params_class,
                                    get_public_key_params_class)
from openssh_key.pascal_style_byte_stream import (PascalStyleByteStream,
                                                  PascalStyleFormatInstruction)
from openssh_key.private_key_list import PrivateKeyList, PublicPrivateKeyPair

from tests.test_key import (ED25519_TEST_HEADER, ED25519_TEST_PRIVATE,
                            ED25519_TEST_PUBLIC, PRIVATE_TEST_FOOTER,
                            RSA_TEST_HEADER, RSA_TEST_PRIVATE, RSA_TEST_PUBLIC,
                            correct_private_key_bytes_ed25519,
                            correct_private_key_bytes_rsa,
                            correct_public_key_bytes_ed25519,
                            correct_public_key_bytes_rsa)


def test_public_private_key_pair_generate():
    key_pair = PublicPrivateKeyPair.generate('ssh-rsa')
    assert type(key_pair.private.params) == RSAPrivateKeyParams
    assert type(key_pair.public.params) == RSAPublicKeyParams
    assert key_pair.private.footer['comment'] == ''


def test_public_private_key_pair_generate_comment():
    key_pair = PublicPrivateKeyPair.generate('ssh-rsa', 'comment')
    assert type(key_pair.private.params) == RSAPrivateKeyParams
    assert type(key_pair.public.params) == RSAPublicKeyParams
    assert key_pair.private.footer['comment'] == 'comment'


def test_public_private_key_pair_generate_kwargs():
    key_pair = PublicPrivateKeyPair.generate(
        'ssh-rsa',
        key_size=2048
    )
    assert type(key_pair.private.params) == RSAPrivateKeyParams
    cryptography_rsa_private_key = key_pair.private.params.convert_to(
        rsa.RSAPrivateKey
    )
    assert cryptography_rsa_private_key.key_size == 2048


def test_private_key_list_header_format_instructions_dict():
    assert PrivateKeyList.HEADER_FORMAT_INSTRUCTIONS_DICT == {
        'auth_magic': '15s',
        'cipher': PascalStyleFormatInstruction.STRING,
        'kdf': PascalStyleFormatInstruction.STRING,
        'kdf_options': PascalStyleFormatInstruction.BYTES,
        'num_keys': '>i'
    }


def test_private_key_list_decipher_bytes_format_instructions_dict():
    assert PrivateKeyList.DECIPHER_BYTES_HEADER_FORMAT_INSTRUCTIONS_DICT == {
        'check_int_1': '>I',
        'check_int_2': '>I'
    }


def correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        num_keys,
        write_byte_stream=None
):
    header = {
        'auth_magic': b'openssh-key-v1\x00',
        'cipher': cipher,
        'kdf': kdf,
        'kdf_options': kdf_options_bytes,
        'num_keys': num_keys
    }
    if write_byte_stream is not None:
        write_byte_stream.write_from_format_instructions_dict(
            PrivateKeyList.HEADER_FORMAT_INSTRUCTIONS_DICT,
            header
        )
    return header


BCRYPT_OPTIONS_TEST = {
    'rounds': 16,
    'salt': b'\x8ccm\xe8\x9e\x07H\xfds\xd9[=\rI=\xe8'
}


def correct_kdf_options_bytes(kdf):
    kdf_options_write_byte_stream = PascalStyleByteStream()
    if kdf == 'bcrypt':
        kdf_options = BCRYPT_OPTIONS_TEST
    elif kdf == 'none':
        kdf_options = {}
    else:
        raise NotImplementedError()
    kdf_options_write_byte_stream.write_from_format_instructions_dict(
        get_kdf_options_class(kdf).FORMAT_INSTRUCTIONS_DICT,
        kdf_options
    )
    kdf_options_bytes = kdf_options_write_byte_stream.getvalue()
    return kdf_options_bytes, kdf_options


def correct_decipher_bytes_header(decipher_byte_stream=None):
    check_int = secrets.randbits(32)
    decipher_bytes_header = {
        'check_int_1': check_int,
        'check_int_2': check_int
    }
    if decipher_byte_stream is not None:
        decipher_byte_stream.write_from_format_instructions_dict(
            PrivateKeyList.DECIPHER_BYTES_HEADER_FORMAT_INSTRUCTIONS_DICT,
            decipher_bytes_header
        )
    return decipher_bytes_header


def correct_decipher_bytes_padding(decipher_byte_stream, cipher, write=False):
    padding_length = (-len(decipher_byte_stream.getvalue())) \
        % get_cipher_class(cipher).BLOCK_SIZE
    padding_bytes = bytes(range(1, 1 + padding_length))
    if write:
        decipher_byte_stream.write(padding_bytes)
    return padding_bytes


def correct_cipher_bytes(
    passphrase,
    kdf,
    kdf_options,
    cipher,
    decipher_byte_stream,
    write_byte_stream=None
):
    cipher_class = get_cipher_class(cipher)
    cipher_bytes = cipher_class.encrypt(
        get_kdf_options_class(kdf)(kdf_options),
        passphrase,
        decipher_byte_stream.getvalue()
    )

    if issubclass(cipher_class, ConfidentialityIntegrityCipher):
        tag = cipher_bytes[len(cipher_bytes) - cipher_class.TAG_LENGTH:]
        cipher_bytes_without_tag = cipher_bytes[
            :len(cipher_bytes) - cipher_class.TAG_LENGTH
        ]
        if write_byte_stream is not None:
            write_byte_stream.write_from_format_instruction(
                PascalStyleFormatInstruction.BYTES,
                cipher_bytes_without_tag
            )
            write_byte_stream.write(tag)
    elif write_byte_stream is not None:
        write_byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            cipher_bytes
        )
    return cipher_bytes


def private_key_list_from_bytes_test_assertions(
    write_byte_stream,
    mocker,
    passphrase,
    pass_passphrase,
    getpass_assert_called,
    header,
    cipher_bytes,
    public_keys,
    private_keys,
    kdf_options,
    decipher_byte_stream,
    decipher_bytes_header,
    padding_bytes
):
    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    if pass_passphrase:
        private_key_list = PrivateKeyList.from_bytes(
            write_byte_stream.getvalue(),
            passphrase=passphrase
        )
    else:
        private_key_list = PrivateKeyList.from_bytes(
            write_byte_stream.getvalue())

    if getpass_assert_called:
        getpass.getpass.assert_called_once()  # pylint: disable=no-member
    else:
        getpass.getpass.assert_not_called()  # pylint: disable=no-member

    assert private_key_list.byte_string == write_byte_stream.getvalue()
    assert private_key_list.header == header
    assert private_key_list.cipher_bytes == cipher_bytes

    for i, public_key in enumerate(public_keys):
        assert private_key_list[i].public.header == public_key.header
        assert private_key_list[i].public.params == public_key.params
        assert private_key_list[i].public.footer == public_key.footer

    assert private_key_list.kdf_options == kdf_options

    assert private_key_list.decipher_bytes == decipher_byte_stream.getvalue()
    assert private_key_list.decipher_bytes_header == decipher_bytes_header

    for i, private_key in enumerate(private_keys):
        assert private_key_list[i].private.header == private_key.header
        assert private_key_list[i].private.params == private_key.params
        assert private_key_list[i].private.footer == private_key.footer

    assert private_key_list.decipher_padding == padding_bytes


def test_private_key_list_from_bytes_invalid_auth_magic():
    write_byte_stream = PascalStyleByteStream()
    header = {
        'auth_magic': b'not_openssh_key',
        'cipher': 'none',
        'kdf': 'none',
        'kdf_options': b'',
        'num_keys': 0
    }
    write_byte_stream.write_from_format_instructions_dict(
        PrivateKeyList.HEADER_FORMAT_INSTRUCTIONS_DICT,
        header
    )
    with pytest.raises(ValueError, match='Not an openssh-key-v1 key'):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_negative_num_keys():
    write_byte_stream = PascalStyleByteStream()
    _ = correct_header(
        'none',
        'none',
        b'',
        -1,
        write_byte_stream
    )
    with pytest.raises(
        ValueError,
        match='Cannot parse negative number of keys'
    ):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_one_key_none(mocker):
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    header = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _, public_key = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    decipher_bytes_header = correct_decipher_bytes_header(
        decipher_byte_stream
    )
    _, private_key = correct_private_key_bytes_ed25519(decipher_byte_stream)
    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    cipher_bytes = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    private_key_list_from_bytes_test_assertions(
        write_byte_stream,
        mocker,
        passphrase,
        False,
        False,
        header,
        cipher_bytes,
        [public_key],
        [private_key],
        kdf_options,
        decipher_byte_stream,
        decipher_bytes_header,
        padding_bytes
    )


def test_private_key_list_from_bytes_one_key_bcrypt_aes256ctr(mocker):
    kdf = 'bcrypt'
    cipher = 'aes256-ctr'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    header = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _, public_key = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    decipher_bytes_header = correct_decipher_bytes_header(
        decipher_byte_stream
    )
    _, private_key = correct_private_key_bytes_ed25519(decipher_byte_stream)
    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    cipher_bytes = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    private_key_list_from_bytes_test_assertions(
        write_byte_stream,
        mocker,
        passphrase,
        False,
        True,
        header,
        cipher_bytes,
        [public_key],
        [private_key],
        kdf_options,
        decipher_byte_stream,
        decipher_bytes_header,
        padding_bytes
    )


def test_private_key_list_from_bytes_one_key_bcrypt_aes256gcm(mocker):
    kdf = 'bcrypt'
    cipher = 'aes256-gcm@openssh.com'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    header = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _, public_key = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    decipher_bytes_header = correct_decipher_bytes_header(
        decipher_byte_stream
    )
    _, private_key = correct_private_key_bytes_ed25519(decipher_byte_stream)
    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    cipher_bytes = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    private_key_list_from_bytes_test_assertions(
        write_byte_stream,
        mocker,
        passphrase,
        False,
        True,
        header,
        cipher_bytes,
        [public_key],
        [private_key],
        kdf_options,
        decipher_byte_stream,
        decipher_bytes_header,
        padding_bytes
    )


def test_private_key_list_from_bytes_two_keys_bcrypt_aes256ctr(mocker):
    kdf = 'bcrypt'
    cipher = 'aes256-ctr'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    header = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        2,
        write_byte_stream
    )

    _, public_key_0 = correct_public_key_bytes_ed25519(write_byte_stream)
    _, public_key_1 = correct_public_key_bytes_rsa(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    decipher_bytes_header = correct_decipher_bytes_header(
        decipher_byte_stream
    )
    _, private_key_0 = correct_private_key_bytes_ed25519(decipher_byte_stream)
    _, private_key_1 = correct_private_key_bytes_rsa(decipher_byte_stream)
    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    cipher_bytes = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    private_key_list_from_bytes_test_assertions(
        write_byte_stream,
        mocker,
        passphrase,
        False,
        True,
        header,
        cipher_bytes,
        [public_key_0, public_key_1],
        [private_key_0, private_key_1],
        kdf_options,
        decipher_byte_stream,
        decipher_bytes_header,
        padding_bytes
    )


def test_private_key_list_from_bytes_two_keys_bcrypt_aes256gcm(mocker):
    kdf = 'bcrypt'
    cipher = 'aes256-gcm@openssh.com'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    header = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        2,
        write_byte_stream
    )

    _, public_key_0 = correct_public_key_bytes_ed25519(write_byte_stream)
    _, public_key_1 = correct_public_key_bytes_rsa(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    decipher_bytes_header = correct_decipher_bytes_header(
        decipher_byte_stream
    )
    _, private_key_0 = correct_private_key_bytes_ed25519(decipher_byte_stream)
    _, private_key_1 = correct_private_key_bytes_rsa(decipher_byte_stream)
    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    cipher_bytes = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    private_key_list_from_bytes_test_assertions(
        write_byte_stream,
        mocker,
        passphrase,
        False,
        True,
        header,
        cipher_bytes,
        [public_key_0, public_key_1],
        [private_key_0, private_key_1],
        kdf_options,
        decipher_byte_stream,
        decipher_bytes_header,
        padding_bytes
    )


def test_private_key_list_from_bytes_one_key_none_extra_bytes_public_key():
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    remainder = b'\x00'
    public_key_bytes += remainder
    write_byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.BYTES,
        public_key_bytes
    )

    decipher_byte_stream = PascalStyleByteStream()

    _ = correct_decipher_bytes_header(
        decipher_byte_stream
    )
    _, _ = correct_private_key_bytes_ed25519(decipher_byte_stream)
    _ = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    with pytest.warns(UserWarning, match='Excess bytes in key'):
        private_key_list = PrivateKeyList.from_bytes(
            write_byte_stream.getvalue()
        )

    assert private_key_list[0].public.clear['remainder'] == remainder


def test_private_key_list_from_bytes_one_key_none_bad_decipher_bytes_header():
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _, _ = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    check_int = secrets.randbits(32)
    decipher_bytes_header = {
        'check_int_1': check_int,
        'check_int_2': check_int ^ 1
    }
    decipher_byte_stream.write_from_format_instructions_dict(
        PrivateKeyList.DECIPHER_BYTES_HEADER_FORMAT_INSTRUCTIONS_DICT,
        decipher_bytes_header
    )

    _, _ = correct_private_key_bytes_ed25519(decipher_byte_stream)
    _ = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    with pytest.warns(
        UserWarning,
        match='Cipher header check numbers do not match'
    ):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_one_key_bcrypt_aes256ctr_bad_passphrase(mocker):
    kdf = 'bcrypt'
    cipher = 'aes256-ctr'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _, _ = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    _ = correct_decipher_bytes_header(decipher_byte_stream)
    _, _ = correct_private_key_bytes_ed25519(decipher_byte_stream)
    _ = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    mocker.patch.object(getpass, 'getpass', return_value='wrong_passphrase')

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(Exception):
            PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_one_key_none_inconsistent_key_types():
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _, _ = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    _ = correct_decipher_bytes_header(decipher_byte_stream)

    _, _ = correct_private_key_bytes_rsa(decipher_byte_stream)
    _ = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    with pytest.warns(
        UserWarning,
        match='Inconsistency between private and public key types for key 0'
    ):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_one_key_none_inconsistent_key_params():
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    public_key_write_byte_stream = PascalStyleByteStream()
    public_key_header = {
        'key_type': 'ssh-ed25519'
    }
    public_key_write_byte_stream.write_from_format_instructions_dict(
        PublicKey.HEADER_FORMAT_INSTRUCTIONS_DICT,
        public_key_header
    )
    public_key_params = {
        'public': bytes([
            byte ^ 255 for byte in ED25519_TEST_PUBLIC['public']
        ])
    }
    public_key_write_byte_stream.write_from_format_instructions_dict(
        Ed25519PublicKeyParams.FORMAT_INSTRUCTIONS_DICT,
        public_key_params
    )
    public_key_bytes = public_key_write_byte_stream.getvalue()
    write_byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.BYTES,
        public_key_bytes
    )

    decipher_byte_stream = PascalStyleByteStream()

    _ = correct_decipher_bytes_header(decipher_byte_stream)

    _, _ = correct_private_key_bytes_ed25519(decipher_byte_stream)
    _ = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    with pytest.warns(
        UserWarning,
        match='Inconsistency between private and public values for key 0'
    ):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_one_key_none_unexpected_padding_bytes():
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _ = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    _ = correct_decipher_bytes_header(decipher_byte_stream)

    _, _ = correct_private_key_bytes_ed25519(decipher_byte_stream)
    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=False
    )
    padding_bytes = bytes([
        byte ^ 255 for byte in padding_bytes
    ])
    decipher_byte_stream.write(padding_bytes)

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    with pytest.warns(
        UserWarning,
        match='Incorrect padding at end of ciphertext'
    ):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_one_key_none_excess_padding_bytes():
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _ = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    _ = correct_decipher_bytes_header(decipher_byte_stream)

    _, _ = correct_private_key_bytes_ed25519(decipher_byte_stream)
    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=False
    )
    decipher_byte_stream.write(padding_bytes + padding_bytes)

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    with pytest.warns(
        UserWarning,
        match='Incorrect padding at end of ciphertext'
    ):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_one_key_none_no_padding_bytes():
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _ = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    _ = correct_decipher_bytes_header(decipher_byte_stream)

    _, _ = correct_private_key_bytes_ed25519(decipher_byte_stream)

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    with pytest.warns(
        UserWarning,
        match='Incorrect padding at end of ciphertext'
    ):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_one_key_none_insufficient_padding_bytes():
    kdf = 'none'
    cipher = 'none'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    _ = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _ = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    _ = correct_decipher_bytes_header(decipher_byte_stream)

    _, _ = correct_private_key_bytes_ed25519(decipher_byte_stream)

    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=False
    )
    decipher_byte_stream.write(padding_bytes[:-1])

    passphrase = 'passphrase'
    _ = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    with pytest.warns(
        UserWarning,
        match='Incorrect padding at end of ciphertext'
    ):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_from_bytes_passphrase(mocker):
    kdf = 'bcrypt'
    cipher = 'aes256-ctr'

    write_byte_stream = PascalStyleByteStream()
    kdf_options_bytes, kdf_options = correct_kdf_options_bytes(kdf)
    header = correct_header(
        cipher,
        kdf,
        kdf_options_bytes,
        1,
        write_byte_stream
    )

    _, public_key = correct_public_key_bytes_ed25519(write_byte_stream)

    decipher_byte_stream = PascalStyleByteStream()

    decipher_bytes_header = correct_decipher_bytes_header(
        decipher_byte_stream
    )
    _, private_key = correct_private_key_bytes_ed25519(decipher_byte_stream)
    padding_bytes = correct_decipher_bytes_padding(
        decipher_byte_stream, cipher, write=True
    )

    passphrase = 'passphrase'
    cipher_bytes = correct_cipher_bytes(
        passphrase,
        kdf,
        kdf_options,
        cipher,
        decipher_byte_stream,
        write_byte_stream
    )

    private_key_list_from_bytes_test_assertions(
        write_byte_stream,
        mocker,
        passphrase,
        True,
        False,
        header,
        cipher_bytes,
        [public_key],
        [private_key],
        kdf_options,
        decipher_byte_stream,
        decipher_bytes_header,
        padding_bytes
    )


def test_private_key_list_from_string():
    private_key_list = PrivateKeyList.from_list([
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {},
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER,
                {}
            )
        )
    ])
    private_keys_bytes = private_key_list.pack_bytes()
    private_keys_b64 = base64.b64encode(private_keys_bytes).decode()
    private_keys_wrapped = ''.join([
        (
            private_keys_b64[
                i:min(i + PrivateKeyList.WRAP_COL, len(private_keys_b64))
            ] + '\n'
        )
        for i in range(0, len(private_keys_b64), PrivateKeyList.WRAP_COL)
    ])
    private_keys_string = PrivateKeyList.OPENSSH_PRIVATE_KEY_HEADER + '\n' + \
        private_keys_wrapped + '\n' + \
        PrivateKeyList.OPENSSH_PRIVATE_KEY_FOOTER
    assert PrivateKeyList.from_string(private_keys_string) == private_key_list


def test_private_key_list_from_string_incorrect_header():
    with pytest.raises(ValueError, match='Not an openssh private key'):
        PrivateKeyList.from_string(
            'not an openssh private key\n' +
            PrivateKeyList.OPENSSH_PRIVATE_KEY_FOOTER
        )


def test_private_key_list_from_string_incorrect_footer():
    with pytest.raises(ValueError, match='Not an openssh private key'):
        PrivateKeyList.from_string(
            PrivateKeyList.OPENSSH_PRIVATE_KEY_HEADER +
            '\nnot an openssh private key'
        )


def test_private_key_list_from_string_passphrase(mocker):
    private_key_list = PrivateKeyList.from_list(
        [
            PublicPrivateKeyPair(
                PublicKey(
                    ED25519_TEST_HEADER,
                    ED25519_TEST_PUBLIC,
                    {},
                    {}
                ),
                PrivateKey(
                    ED25519_TEST_HEADER,
                    ED25519_TEST_PRIVATE,
                    PRIVATE_TEST_FOOTER,
                    {}
                )
            )
        ],
        'aes256-ctr',
        'bcrypt',
        get_kdf_options_class('bcrypt').generate_options()
    )
    passphrase = 'passphrase'
    private_keys_bytes = private_key_list.pack_bytes(passphrase=passphrase)
    private_keys_b64 = base64.b64encode(private_keys_bytes).decode()
    private_keys_wrapped = ''.join([
        (
            private_keys_b64[
                i:min(i + PrivateKeyList.WRAP_COL, len(private_keys_b64))
            ] + '\n'
        )
        for i in range(0, len(private_keys_b64), PrivateKeyList.WRAP_COL)
    ])
    private_keys_string = PrivateKeyList.OPENSSH_PRIVATE_KEY_HEADER + '\n' + \
        private_keys_wrapped + '\n' + \
        PrivateKeyList.OPENSSH_PRIVATE_KEY_FOOTER

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    assert PrivateKeyList.from_string(
        private_keys_string,
        passphrase
    ) == private_key_list

    getpass.getpass.assert_not_called()  # pylint: disable=no-member


def test_private_key_list_from_list_one_key():
    key_pair_0 = PublicPrivateKeyPair(
        PublicKey(
            ED25519_TEST_HEADER,
            ED25519_TEST_PUBLIC,
            {}
        ),
        PrivateKey(
            ED25519_TEST_HEADER,
            ED25519_TEST_PRIVATE,
            PRIVATE_TEST_FOOTER
        )
    )

    private_key_list = PrivateKeyList.from_list([key_pair_0])

    assert private_key_list.header == {
        'cipher': 'none',
        'kdf': 'none'
    }
    assert private_key_list.kdf_options == {}
    assert private_key_list[0] == key_pair_0


def test_private_key_list_from_list_two_keys():
    key_pair_0 = PublicPrivateKeyPair(
        PublicKey(
            ED25519_TEST_HEADER,
            ED25519_TEST_PUBLIC,
            {}
        ),
        PrivateKey(
            ED25519_TEST_HEADER,
            ED25519_TEST_PRIVATE,
            PRIVATE_TEST_FOOTER
        )
    )
    key_pair_1 = PublicPrivateKeyPair(
        PublicKey(
            RSA_TEST_HEADER,
            RSA_TEST_PUBLIC,
            {}
        ),
        PrivateKey(
            RSA_TEST_HEADER,
            RSA_TEST_PRIVATE,
            PRIVATE_TEST_FOOTER
        )
    )

    private_key_list = PrivateKeyList.from_list([key_pair_0, key_pair_1])

    assert private_key_list.header == {
        'cipher': 'none',
        'kdf': 'none'
    }
    assert private_key_list.kdf_options == {}
    assert private_key_list[0] == key_pair_0
    assert private_key_list[1] == key_pair_1


def test_private_key_list_from_list_bcrypt_aes256_ctr():
    key_pair_0 = PublicPrivateKeyPair(
        PublicKey(
            ED25519_TEST_HEADER,
            ED25519_TEST_PUBLIC,
            {}
        ),
        PrivateKey(
            ED25519_TEST_HEADER,
            ED25519_TEST_PRIVATE,
            PRIVATE_TEST_FOOTER
        )
    )

    private_key_list = PrivateKeyList.from_list(
        [key_pair_0],
        'aes256-ctr',
        'bcrypt',
        BCRYPT_OPTIONS_TEST
    )

    assert private_key_list.header == {
        'cipher': 'aes256-ctr',
        'kdf': 'bcrypt'
    }
    assert private_key_list.kdf_options == BCRYPT_OPTIONS_TEST
    assert private_key_list[0] == key_pair_0


def test_private_key_list_from_list_invalid_private_key():
    key_pair_0 = PublicPrivateKeyPair(
        PublicKey(
            ED25519_TEST_HEADER,
            ED25519_TEST_PUBLIC,
            {}
        ),
        'not a private key'
    )

    with pytest.raises(ValueError, match='Not a key pair'):
        PrivateKeyList.from_list([key_pair_0])


def test_private_key_list_from_list_invalid_public_key():
    key_pair_0 = PublicPrivateKeyPair(
        'not a public key',
        PrivateKey(
            ED25519_TEST_HEADER,
            ED25519_TEST_PRIVATE,
            PRIVATE_TEST_FOOTER
        )
    )

    with pytest.raises(ValueError, match='Not a key pair'):
        PrivateKeyList.from_list([key_pair_0])


def test_private_key_list_from_list_invalid_key_pair():
    with pytest.raises(ValueError, match='Not a key pair'):
        PrivateKeyList.from_list(['not a key pair'])


def private_key_list_pack_bytes_test_assertions(
    pack_bytes,
    passphrase,
    getpass_assert_call_count,
    cipher,
    kdf,
    key_pairs,
    kdf_options
):
    pack_byte_stream = PascalStyleByteStream(pack_bytes)

    assert getpass.getpass.call_count \
        == getpass_assert_call_count  # pylint: disable=no-member

    kdf_options_byte_stream = PascalStyleByteStream()
    kdf_options_byte_stream.write_from_format_instructions_dict(
        get_kdf_options_class(kdf).FORMAT_INSTRUCTIONS_DICT,
        kdf_options
    )
    kdf_options_bytes = kdf_options_byte_stream.getvalue()

    assert pack_byte_stream.read_from_format_instructions_dict(
        PrivateKeyList.HEADER_FORMAT_INSTRUCTIONS_DICT
    ) == {
        'auth_magic': b'openssh-key-v1\x00',
        'cipher': cipher,
        'kdf': kdf,
        'kdf_options': kdf_options_bytes,
        'num_keys': len(key_pairs)
    }

    for key_pair in key_pairs:
        public_key_byte_stream = \
            PascalStyleByteStream(
                pack_byte_stream.read_from_format_instruction(
                    PascalStyleFormatInstruction.BYTES
                )
            )
        assert public_key_byte_stream.read_from_format_instructions_dict(
            PublicKey.HEADER_FORMAT_INSTRUCTIONS_DICT
        ) == key_pair.public.header
        assert public_key_byte_stream.read_from_format_instructions_dict(
            get_public_key_params_class(
                key_pair.public.header['key_type']
            ).FORMAT_INSTRUCTIONS_DICT
        ) == key_pair.public.params
        assert public_key_byte_stream.read_from_format_instructions_dict(
            PublicKey.FOOTER_FORMAT_INSTRUCTIONS_DICT
        ) == key_pair.public.footer
        assert public_key_byte_stream.read() == b''

    cipher_bytes = pack_byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.BYTES
    )
    cipher_class = get_cipher_class(cipher)
    if issubclass(cipher_class, ConfidentialityIntegrityCipher):
        cipher_bytes += pack_byte_stream.read_fixed_bytes(
            cipher_class.TAG_LENGTH
        )

    decipher_bytes = cipher_class.decrypt(
        get_kdf_options_class(kdf)(kdf_options),
        passphrase,
        cipher_bytes
    )

    decipher_byte_stream = PascalStyleByteStream(decipher_bytes)

    check_int_1 = decipher_byte_stream.read_from_format_instruction('>I')
    check_int_2 = decipher_byte_stream.read_from_format_instruction('>I')
    assert check_int_1 == check_int_2

    for key_pair in key_pairs:
        assert decipher_byte_stream.read_from_format_instructions_dict(
            PrivateKey.HEADER_FORMAT_INSTRUCTIONS_DICT
        ) == key_pair.private.header
        assert decipher_byte_stream.read_from_format_instructions_dict(
            get_private_key_params_class(
                key_pair.private.header['key_type']
            ).FORMAT_INSTRUCTIONS_DICT
        ) == key_pair.private.params
        assert decipher_byte_stream.read_from_format_instructions_dict(
            PrivateKey.FOOTER_FORMAT_INSTRUCTIONS_DICT
        ) == key_pair.private.footer

    cipher_block_size = cipher_class.BLOCK_SIZE
    assert len(decipher_byte_stream.getvalue()) \
        % cipher_block_size == 0
    assert bytes(
        range(1, 1 + cipher_block_size)
    ).startswith(decipher_byte_stream.read())

    assert pack_byte_stream.read() == b''


def test_private_key_list_pack_bytes_one_key_none(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes()

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        0,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_bytes_two_keys_none(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        ),
        PublicPrivateKeyPair(
            PublicKey(
                RSA_TEST_HEADER,
                RSA_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                RSA_TEST_HEADER,
                RSA_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes()

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        0,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_bytes_one_key_bcrypt_aes256_ctr(mocker):
    cipher = 'aes256-ctr'
    kdf = 'bcrypt'
    kdf_options = BCRYPT_OPTIONS_TEST

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes()

    generated_kdf_options = PrivateKeyList.from_bytes(pack_bytes).kdf_options

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        2,
        cipher,
        kdf,
        key_pairs,
        generated_kdf_options
    )

    assert kdf_options != generated_kdf_options


def test_private_key_list_pack_bytes_one_key_bcrypt_aes256_gcm(mocker):
    cipher = 'aes256-gcm@openssh.com'
    kdf = 'bcrypt'
    kdf_options = BCRYPT_OPTIONS_TEST

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes()

    generated_kdf_options = PrivateKeyList.from_bytes(pack_bytes).kdf_options

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        2,
        cipher,
        kdf,
        key_pairs,
        generated_kdf_options
    )

    assert kdf_options != generated_kdf_options


def test_private_key_list_pack_bytes_two_keys_include_indices(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes(include_indices=[0])

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        0,
        cipher,
        kdf,
        [key_pairs[0]],
        kdf_options
    )


def test_private_key_list_pack_bytes_two_keys_invalid_include_indices(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    with pytest.raises(IndexError):
        private_key_list.pack_bytes(include_indices=[2])


def test_private_key_list_pack_bytes_override_public_with_private(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                RSA_TEST_HEADER,
                RSA_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes(override_public_with_private=True)

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        0,
        cipher,
        kdf,
        [
            PublicPrivateKeyPair(
                PublicKey(
                    ED25519_TEST_HEADER,
                    ED25519_TEST_PUBLIC,
                    {}
                ),
                PrivateKey(
                    ED25519_TEST_HEADER,
                    ED25519_TEST_PRIVATE,
                    PRIVATE_TEST_FOOTER
                )
            )
        ],
        kdf_options
    )


def test_private_key_list_pack_bytes_no_override_public_with_private(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                RSA_TEST_HEADER,
                RSA_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes(
        override_public_with_private=False)

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        0,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_bytes_header_none(mocker):
    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList(key_pairs)

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes()

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        0,
        'none',
        'none',
        key_pairs,
        {}
    )


def test_private_key_list_pack_bytes_header_no_cipher(mocker):
    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList(key_pairs, header={'kdf': 'bcrypt'})

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes()

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        0,
        'none',
        'none',
        key_pairs,
        {}
    )


def test_private_key_list_pack_bytes_header_no_kdf(mocker):
    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList(
        key_pairs,
        header={'cipher': 'aes256-ctr'}
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes()

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        0,
        'none',
        'none',
        key_pairs,
        {}
    )


def test_private_key_list_pack_bytes_header_retain_kdf_options(mocker):
    cipher = 'aes256-ctr'
    kdf = 'bcrypt'
    kdf_options = BCRYPT_OPTIONS_TEST

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes(
        retain_kdf_options_if_present=True
    )

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        1,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_bytes_passphrase(mocker):
    cipher = 'aes256-ctr'
    kdf = 'bcrypt'
    kdf_options = BCRYPT_OPTIONS_TEST

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_bytes = private_key_list.pack_bytes(passphrase=passphrase)

    generated_kdf_options = PrivateKeyList.from_bytes(pack_bytes).kdf_options

    private_key_list_pack_bytes_test_assertions(
        pack_bytes,
        passphrase,
        1,
        cipher,
        kdf,
        key_pairs,
        generated_kdf_options
    )

    assert kdf_options != generated_kdf_options


def private_key_list_pack_string_test_assertions(
    pack_string,
    *args
):
    pack_string_lines = pack_string.splitlines()
    assert pack_string_lines[0] == PrivateKeyList.OPENSSH_PRIVATE_KEY_HEADER
    assert pack_string_lines[-1] == PrivateKeyList.OPENSSH_PRIVATE_KEY_FOOTER
    pack_bytes = base64.b64decode(
        ''.join(pack_string_lines[1:-1])
    )
    private_key_list_pack_bytes_test_assertions(pack_bytes, *args)


def test_private_key_list_pack_string_one_key_none(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_string = private_key_list.pack_string()

    private_key_list_pack_string_test_assertions(
        pack_string,
        passphrase,
        0,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_string_two_keys_none(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        ),
        PublicPrivateKeyPair(
            PublicKey(
                RSA_TEST_HEADER,
                RSA_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                RSA_TEST_HEADER,
                RSA_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_string = private_key_list.pack_string()

    private_key_list_pack_string_test_assertions(
        pack_string,
        passphrase,
        0,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_string_one_key_bcrypt_aes256_ctr(mocker):
    cipher = 'aes256-ctr'
    kdf = 'bcrypt'
    kdf_options = BCRYPT_OPTIONS_TEST

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_string = private_key_list.pack_string()

    generated_kdf_options = PrivateKeyList.from_string(pack_string).kdf_options

    private_key_list_pack_string_test_assertions(
        pack_string,
        passphrase,
        2,
        cipher,
        kdf,
        key_pairs,
        generated_kdf_options
    )

    assert kdf_options != generated_kdf_options


def test_private_key_list_pack_string_two_keys_include_indices(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_string = private_key_list.pack_string()

    private_key_list_pack_string_test_assertions(
        pack_string,
        passphrase,
        0,
        cipher,
        kdf,
        [key_pairs[0]],
        kdf_options
    )


def test_private_key_list_pack_string_two_keys_invalid_include_indices(
    mocker
):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    with pytest.raises(IndexError):
        private_key_list.pack_string(include_indices=[2])


def test_private_key_list_pack_string_override_public_with_private(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                RSA_TEST_HEADER,
                RSA_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_string = private_key_list.pack_string(
        override_public_with_private=True
    )

    private_key_list_pack_string_test_assertions(
        pack_string,
        passphrase,
        0,
        cipher,
        kdf,
        [
            PublicPrivateKeyPair(
                PublicKey(
                    ED25519_TEST_HEADER,
                    ED25519_TEST_PUBLIC,
                    {}
                ),
                PrivateKey(
                    ED25519_TEST_HEADER,
                    ED25519_TEST_PRIVATE,
                    PRIVATE_TEST_FOOTER
                )
            )
        ],
        kdf_options
    )


def test_private_key_list_pack_string_no_override_public_with_private(mocker):
    cipher = 'none'
    kdf = 'none'
    kdf_options = {}

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                RSA_TEST_HEADER,
                RSA_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_string = private_key_list.pack_string(
        override_public_with_private=False
    )

    private_key_list_pack_string_test_assertions(
        pack_string,
        passphrase,
        0,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_string_one_key_retain_kdf_options(mocker):
    cipher = 'aes256-ctr'
    kdf = 'bcrypt'
    kdf_options = BCRYPT_OPTIONS_TEST

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_string = private_key_list.pack_string(
        retain_kdf_options_if_present=True
    )

    private_key_list_pack_string_test_assertions(
        pack_string,
        passphrase,
        1,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_string_passphrase(mocker):
    cipher = 'aes256-ctr'
    kdf = 'bcrypt'
    kdf_options = BCRYPT_OPTIONS_TEST

    passphrase = 'passphrase'

    key_pairs = [
        PublicPrivateKeyPair(
            PublicKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PUBLIC,
                {}
            ),
            PrivateKey(
                ED25519_TEST_HEADER,
                ED25519_TEST_PRIVATE,
                PRIVATE_TEST_FOOTER
            )
        )
    ]

    private_key_list = PrivateKeyList.from_list(
        key_pairs,
        cipher,
        kdf,
        kdf_options
    )

    mocker.patch.object(getpass, 'getpass', return_value=passphrase)

    pack_string = private_key_list.pack_string(passphrase=passphrase)

    generated_kdf_options = PrivateKeyList.from_string(pack_string).kdf_options

    private_key_list_pack_string_test_assertions(
        pack_string,
        passphrase,
        1,
        cipher,
        kdf,
        key_pairs,
        generated_kdf_options
    )

    assert kdf_options != generated_kdf_options
