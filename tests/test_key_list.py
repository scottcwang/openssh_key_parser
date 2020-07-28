import warnings
import secrets
import getpass

import pytest

from openssh_key.key_list import (
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
    RSAPublicKeyParams,
    RSAPrivateKeyParams,
    create_public_key_params,
    create_private_key_params
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


ED25519_TEST_HEADER = {
    'key_type': 'ssh-ed25519'
}

ED25519_TEST_PUBLIC = {
    'public': bytes.fromhex(
        '2751e7d2ba43820988d1b05f2c322e9bfb432c633e6dbc337e7f05d56126c3a3'
    )
}

ED25519_TEST_PRIVATE = {
    'private_public': bytes.fromhex(
        'd783bfa87ec767c0daf35d64a3eeb591369cab440da8c1c5ddab1756b03ac8ab'
        '2751e7d2ba43820988d1b05f2c322e9bfb432c633e6dbc337e7f05d56126c3a3'
    ),
    'public': bytes.fromhex(
        '2751e7d2ba43820988d1b05f2c322e9bfb432c633e6dbc337e7f05d56126c3a3'
    )
}

PRIVATE_TEST_FOOTER = {
    'comment': 'comment'
}

RSA_TEST_HEADER = {
    'key_type': 'ssh-rsa'
}

RSA_TEST_PUBLIC = {
    'e': 65537,
    'n': int(
        '2283305350490415445938955587508601192587709196196095570586178349'
        '3019315221189120363317580685288021091497919773654925550564812490'
        '7968037712820247801639674225542097512776888421123115764300713153'
        '5182870254621384897386281752267380680840594977375700959061058058'
        '6272025555434425135640999935536685062998675329937670482024388465'
        '1094421654886887607362710733448838954578795481327899067798775959'
        '7174507604476894911009084965102074510264640400432535975549901720'
        '0188217124698379610854430469218406750035681701070768737312867205'
        '5674537387323584344689645957410347874074685381585047191574256651'
        '52240873255314150689127380129563432352431'
    )
}

RSA_TEST_PRIVATE = {
    'd': int(
        '1268766207620267319144284078158913737743055156596628048187082975'
        '2129093525947849249598491475290810749486240511423950192638033118'
        '3506599773986831319595221268467683371573247869631513599776295389'
        '0424563011162350638694420290405743354962417371730334037660047779'
        '4379790876180714102943959818918160122361761439955141903513046455'
        '5986948049699678341167071863675561504168194520387072495567759999'
        '5876258166902017706367558789865334734548233690114341008842728412'
        '1327143109415407738336445383809844276198318274273081216177855411'
        '3482108586054025213464268711303240386115387686999121085530803388'
        '58580245272655097723658862898101516632945'
    ),
    'e': 65537,
    'iqmp': int(
        '1241913039349041115466450441681349490053728223375886918395381991'
        '0342299114260708527396132668974729868938802898452708601517767672'
        '1819773840844391951880095970447671421843371199750136538562195971'
        '4233911339684677260695227585966385563104728924959129576355959556'
        '7333065635860785686188030805670201190489445471058341'
    ),
    'n': int(
        '2283305350490415445938955587508601192587709196196095570586178349'
        '3019315221189120363317580685288021091497919773654925550564812490'
        '7968037712820247801639674225542097512776888421123115764300713153'
        '5182870254621384897386281752267380680840594977375700959061058058'
        '6272025555434425135640999935536685062998675329937670482024388465'
        '1094421654886887607362710733448838954578795481327899067798775959'
        '7174507604476894911009084965102074510264640400432535975549901720'
        '0188217124698379610854430469218406750035681701070768737312867205'
        '5674537387323584344689645957410347874074685381585047191574256651'
        '52240873255314150689127380129563432352431'
    ),
    'p': int(
        '1568598642909442150790444681604647073561768235788188497618275333'
        '9231307217189488730437942645635675966066945970641897157585659175'
        '3051411658256077408456111567225244218205396756138949662433706914'
        '2282859379501594178166153415158065736761992076256437295980901856'
        '37434898215022254811579944390223997250026710246369833'
    ),
    'q': int(
        '1455633893865503312566582200526013372055671451553169248235609130'
        '2065340979266028245478469402241744116497864909028098169270301724'
        '7120232046330237700560786675720114547570992868330030216078165542'
        '6309302131587079317114345811045788371437429407483171503609902473'
        '05951782299025425731762581855379169427745358634109207'
    )
}

BCRYPT_OPTIONS_TEST = {
    'rounds': 16,
    'salt': b'\x8ccm\xe8\x9e\x07H\xfds\xd9[=\rI=\xe8'
}


def correct_public_key_bytes_ed25519(write_byte_stream=None):
    public_key_write_byte_stream = PascalStyleByteStream()
    public_key_write_byte_stream.write_from_format_instructions_dict(
        PublicKey.header_format_instructions_dict(),
        ED25519_TEST_HEADER
    )
    public_key_write_byte_stream.write_from_format_instructions_dict(
        Ed25519PublicKeyParams.public_format_instructions_dict(),
        ED25519_TEST_PUBLIC
    )
    public_key_bytes = public_key_write_byte_stream.getvalue()
    public_key = PublicKey.from_bytes(public_key_bytes)
    if write_byte_stream is not None:
        write_byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            public_key_bytes
        )
    return public_key_bytes, public_key


def correct_private_key_bytes_ed25519(decipher_byte_stream=None):
    private_key_write_byte_stream = PascalStyleByteStream()
    private_key_write_byte_stream.write_from_format_instructions_dict(
        PrivateKey.header_format_instructions_dict(),
        ED25519_TEST_HEADER
    )
    private_key_write_byte_stream.write_from_format_instructions_dict(
        Ed25519PrivateKeyParams.private_format_instructions_dict(),
        ED25519_TEST_PRIVATE
    )
    private_key_write_byte_stream.write_from_format_instructions_dict(
        PrivateKey.footer_format_instructions_dict(),
        PRIVATE_TEST_FOOTER
    )
    private_key_bytes = private_key_write_byte_stream.getvalue()
    private_key = PrivateKey.from_bytes(private_key_bytes)
    if decipher_byte_stream is not None:
        decipher_byte_stream.write(private_key_bytes)
    return private_key_bytes, private_key


def correct_public_key_bytes_rsa(write_byte_stream=None):
    public_key_write_byte_stream = PascalStyleByteStream()
    public_key_write_byte_stream.write_from_format_instructions_dict(
        PublicKey.header_format_instructions_dict(),
        RSA_TEST_HEADER
    )
    public_key_write_byte_stream.write_from_format_instructions_dict(
        RSAPublicKeyParams.public_format_instructions_dict(),
        RSA_TEST_PUBLIC
    )
    public_key_bytes = public_key_write_byte_stream.getvalue()
    public_key = PublicKey.from_bytes(public_key_bytes)
    if write_byte_stream is not None:
        write_byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            public_key_bytes
        )
    return public_key_bytes, public_key


def correct_private_key_bytes_rsa(decipher_byte_stream=None):
    private_key_write_byte_stream = PascalStyleByteStream()
    private_key_write_byte_stream.write_from_format_instructions_dict(
        PrivateKey.header_format_instructions_dict(),
        RSA_TEST_HEADER
    )
    private_key_write_byte_stream.write_from_format_instructions_dict(
        RSAPrivateKeyParams.private_format_instructions_dict(),
        RSA_TEST_PRIVATE
    )
    private_key_write_byte_stream.write_from_format_instructions_dict(
        PrivateKey.footer_format_instructions_dict(),
        PRIVATE_TEST_FOOTER
    )
    private_key_bytes = private_key_write_byte_stream.getvalue()
    private_key = PrivateKey.from_bytes(private_key_bytes)
    if decipher_byte_stream is not None:
        decipher_byte_stream.write(private_key_bytes)
    return private_key_bytes, private_key


def test_public_key_init():
    key = PublicKey(
        ED25519_TEST_HEADER,
        Ed25519PublicKeyParams(ED25519_TEST_PUBLIC),
        {}
    )
    assert key.header == ED25519_TEST_HEADER
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}


def test_public_key_from_byte_stream():
    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    key = PublicKey.from_byte_stream(PascalStyleByteStream(public_key_bytes))
    assert key.header == ED25519_TEST_HEADER
    assert isinstance(key.params, Ed25519PublicKeyParams)
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}


def test_public_key_from_bytes():
    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    key = PublicKey.from_bytes(public_key_bytes)
    assert key.header == ED25519_TEST_HEADER
    assert isinstance(key.params, Ed25519PublicKeyParams)
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}
    assert key.bytes == public_key_bytes


def test_public_key_from_bytes_remainder():
    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    remainder = b'\x00'
    public_key_bytes += remainder
    with pytest.warns(UserWarning, match='Excess bytes in key'):
        key = PublicKey.from_bytes(public_key_bytes)
    assert key.header == ED25519_TEST_HEADER
    assert isinstance(key.params, Ed25519PublicKeyParams)
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}
    assert key.bytes == public_key_bytes
    assert key.remainder == remainder


def test_public_key_pack():
    _, public_key = correct_public_key_bytes_ed25519()
    public_key_bytes = public_key.pack_public()
    public_key_byte_stream = PascalStyleByteStream(public_key_bytes)
    assert public_key_byte_stream.read_from_format_instructions_dict(
        PublicKey.header_format_instructions_dict()
    ) == ED25519_TEST_HEADER
    assert public_key_byte_stream.read_from_format_instructions_dict(
        Ed25519PublicKeyParams.public_format_instructions_dict()
    ) == ED25519_TEST_PUBLIC
    assert public_key_byte_stream.read_from_format_instructions_dict(
        PublicKey.footer_format_instructions_dict()
    ) == {}


def test_private_key_init():
    key = PrivateKey(
        ED25519_TEST_HEADER,
        Ed25519PrivateKeyParams(ED25519_TEST_PRIVATE),
        PRIVATE_TEST_FOOTER
    )
    assert key.header == ED25519_TEST_HEADER
    assert key.params == ED25519_TEST_PRIVATE
    assert key.footer == PRIVATE_TEST_FOOTER


def test_private_key_init_invalid_footer():
    with pytest.warns(UserWarning, match='comment missing'):
        PrivateKey(
            ED25519_TEST_HEADER,
            Ed25519PrivateKeyParams(ED25519_TEST_PRIVATE),
            {}
        )


def test_private_key_from_byte_stream():
    private_key_bytes, _ = correct_private_key_bytes_ed25519()
    key = PrivateKey.from_byte_stream(PascalStyleByteStream(private_key_bytes))
    assert key.header == ED25519_TEST_HEADER
    assert key.params == ED25519_TEST_PRIVATE
    assert isinstance(key.params, Ed25519PrivateKeyParams)
    assert key.footer == PRIVATE_TEST_FOOTER


def test_private_key_from_bytes():
    private_key_bytes, _ = correct_private_key_bytes_ed25519()
    key = PrivateKey.from_bytes(private_key_bytes)
    assert key.header == ED25519_TEST_HEADER
    assert key.params == ED25519_TEST_PRIVATE
    assert isinstance(key.params, Ed25519PrivateKeyParams)
    assert key.footer == PRIVATE_TEST_FOOTER


def test_private_key_pack_public():
    _, private_key = correct_private_key_bytes_ed25519()
    public_key_bytes = private_key.pack_public()
    public_key_byte_stream = PascalStyleByteStream(public_key_bytes)
    assert public_key_byte_stream.read_from_format_instructions_dict(
        PublicKey.header_format_instructions_dict()
    ) == ED25519_TEST_HEADER
    assert public_key_byte_stream.read_from_format_instructions_dict(
        Ed25519PublicKeyParams.public_format_instructions_dict()
    ) == ED25519_TEST_PUBLIC
    assert public_key_byte_stream.read_from_format_instructions_dict(
        PublicKey.footer_format_instructions_dict()
    ) == {}


def test_private_key_pack_private():
    _, private_key = correct_private_key_bytes_ed25519()
    private_key_bytes = private_key.pack_private()
    private_key_byte_stream = PascalStyleByteStream(private_key_bytes)
    assert private_key_byte_stream.read_from_format_instructions_dict(
        PrivateKey.header_format_instructions_dict()
    ) == ED25519_TEST_HEADER
    assert private_key_byte_stream.read_from_format_instructions_dict(
        Ed25519PrivateKeyParams.private_format_instructions_dict()
    ) == ED25519_TEST_PRIVATE
    assert private_key_byte_stream.read_from_format_instructions_dict(
        PrivateKey.footer_format_instructions_dict()
    ) == PRIVATE_TEST_FOOTER


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
            PrivateKeyList.header_format_instructions_dict(),
            header
        )
    return header


def correct_kdf_options_bytes(kdf):
    kdf_options_write_byte_stream = PascalStyleByteStream()
    if kdf == 'bcrypt':
        kdf_options = BCRYPT_OPTIONS_TEST
    elif kdf == 'none':
        kdf_options = {}
    else:
        raise NotImplementedError()
    kdf_options_write_byte_stream.write_from_format_instructions_dict(
        create_kdf(kdf).options_format_instructions_dict(),
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
            PrivateKeyList.decipher_bytes_header_format_instructions_dict(),
            decipher_bytes_header
        )
    return decipher_bytes_header


def correct_decipher_bytes_padding(decipher_byte_stream, cipher, write=False):
    padding_length = (-len(decipher_byte_stream.getvalue())) \
        % create_cipher(cipher).block_size()
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
    kdf_result = create_kdf(kdf).derive_key(kdf_options, passphrase)
    cipher_bytes = create_cipher(cipher).encrypt(
        kdf_result['cipher_key'],
        kdf_result['initialization_vector'],
        decipher_byte_stream.getvalue()
    )
    if write_byte_stream is not None:
        write_byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            cipher_bytes
        )
    return cipher_bytes


def private_key_list_from_bytes_test_assertions(
    write_byte_stream,
    mocker,
    passphrase,
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

    private_key_list = PrivateKeyList.from_bytes(write_byte_stream.getvalue())

    if getpass_assert_called:
        getpass.getpass.assert_called_once()
    else:
        getpass.getpass.assert_not_called()

    assert private_key_list.bytes == write_byte_stream.getvalue()
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
    with pytest.raises(ValueError, match='Not an openssh-key-v1 key'):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())


def test_private_key_list_negative_num_keys():
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


def test_private_key_list_one_key_none(mocker):
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
        header,
        cipher_bytes,
        [public_key],
        [private_key],
        kdf_options,
        decipher_byte_stream,
        decipher_bytes_header,
        padding_bytes
    )


def test_private_key_list_one_key_bcrypt_aes256ctr(mocker):
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
        header,
        cipher_bytes,
        [public_key],
        [private_key],
        kdf_options,
        decipher_byte_stream,
        decipher_bytes_header,
        padding_bytes
    )


def test_private_key_list_two_keys_bcrypt_aes256ctr(mocker):
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


def test_private_key_list_one_key_none_extra_bytes_public_key():
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

    assert private_key_list[0].public.remainder == remainder


def test_private_key_list_one_key_none_bad_decipher_bytes_header():
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
        PrivateKeyList.decipher_bytes_header_format_instructions_dict(),
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


def test_private_key_list_one_key_bcrypt_aes256ctr_bad_passphrase(mocker):
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


def test_private_key_list_one_key_none_inconsistent_key_types():
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


def test_private_key_list_one_key_none_inconsistent_key_params():
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
        PublicKey.header_format_instructions_dict(),
        public_key_header
    )
    public_key_params = {
        'public': bytes([
            byte ^ 255 for byte in ED25519_TEST_PUBLIC['public']
        ])
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


def test_private_key_list_one_key_none_unexpected_padding_bytes():
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


def test_private_key_list_one_key_none_excess_padding_bytes():
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


def test_private_key_list_one_key_none_no_padding_bytes():
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


def test_private_key_list_one_key_none_insufficient_padding_bytes():
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


def private_key_list_pack_test_assertions(
    pack_bytes,
    mocker,
    passphrase,
    getpass_assert_called,
    cipher,
    kdf,
    key_pairs,
    kdf_options
):
    pack_byte_stream = PascalStyleByteStream(pack_bytes)

    if getpass_assert_called:
        getpass.getpass.assert_called_once()
    else:
        getpass.getpass.assert_not_called()

    kdf_options_byte_stream = PascalStyleByteStream()
    kdf_options_byte_stream.write_from_format_instructions_dict(
        create_kdf(kdf).options_format_instructions_dict(),
        kdf_options
    )
    kdf_options_bytes = kdf_options_byte_stream.getvalue()

    assert pack_byte_stream.read_from_format_instructions_dict(
        PrivateKeyList.header_format_instructions_dict()
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
            PublicKey.header_format_instructions_dict()
        ) == key_pair.public.header
        assert public_key_byte_stream.read_from_format_instructions_dict(
            create_public_key_params(
                key_pair.public.header['key_type']
            ).public_format_instructions_dict()
        ) == key_pair.public.params
        assert public_key_byte_stream.read_from_format_instructions_dict(
            PublicKey.footer_format_instructions_dict()
        ) == key_pair.public.footer
        assert public_key_byte_stream.read() == b''

    cipher_bytes = pack_byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.BYTES
    )
    kdf_result = create_kdf(kdf).derive_key(kdf_options, passphrase)

    decipher_bytes = create_cipher(cipher).decrypt(
        kdf_result['cipher_key'],
        kdf_result['initialization_vector'],
        cipher_bytes
    )

    decipher_byte_stream = PascalStyleByteStream(decipher_bytes)

    check_int_1 = decipher_byte_stream.read_from_format_instruction('>I')
    check_int_2 = decipher_byte_stream.read_from_format_instruction('>I')
    assert check_int_1 == check_int_2

    for key_pair in key_pairs:
        assert decipher_byte_stream.read_from_format_instructions_dict(
            PrivateKey.header_format_instructions_dict()
        ) == key_pair.private.header
        assert decipher_byte_stream.read_from_format_instructions_dict(
            create_private_key_params(
                key_pair.private.header['key_type']
            ).private_format_instructions_dict()
        ) == key_pair.private.params
        assert decipher_byte_stream.read_from_format_instructions_dict(
            PrivateKey.footer_format_instructions_dict()
        ) == key_pair.private.footer

    cipher_block_size = create_cipher(cipher).block_size()
    assert len(decipher_byte_stream.getvalue()) \
        % cipher_block_size == 0
    assert bytes(
        range(1, 1 + cipher_block_size)
    ).startswith(decipher_byte_stream.read())

    assert pack_byte_stream.read() == b''


def test_private_key_list_pack_one_key_none(mocker):
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

    pack_bytes = private_key_list.pack()

    private_key_list_pack_test_assertions(
        pack_bytes,
        mocker,
        passphrase,
        False,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_two_keys_none(mocker):
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

    pack_bytes = private_key_list.pack()

    private_key_list_pack_test_assertions(
        pack_bytes,
        mocker,
        passphrase,
        False,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_one_key_bcrypt_aes256_ctr(mocker):
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

    pack_bytes = private_key_list.pack()

    private_key_list_pack_test_assertions(
        pack_bytes,
        mocker,
        passphrase,
        True,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )


def test_private_key_list_pack_two_keys_include_indices(mocker):
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

    pack_bytes = private_key_list.pack(include_indices=[0])

    private_key_list_pack_test_assertions(
        pack_bytes,
        mocker,
        passphrase,
        False,
        cipher,
        kdf,
        [key_pairs[0]],
        kdf_options
    )


def test_private_key_list_pack_two_keys_invalid_include_indices(mocker):
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
        private_key_list.pack(include_indices=[2])


def test_private_key_list_pack_override_public_with_private(mocker):
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

    pack_bytes = private_key_list.pack(override_public_with_private=True)

    private_key_list_pack_test_assertions(
        pack_bytes,
        mocker,
        passphrase,
        False,
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


def test_private_key_list_pack_no_override_public_with_private(mocker):
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

    pack_bytes = private_key_list.pack(override_public_with_private=False)

    private_key_list_pack_test_assertions(
        pack_bytes,
        mocker,
        passphrase,
        False,
        cipher,
        kdf,
        key_pairs,
        kdf_options
    )
