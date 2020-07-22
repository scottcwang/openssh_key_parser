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
    RSAPublicKeyParams,
    RSAPrivateKeyParams
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
    'public': bytes.fromhex('2751e7d2ba43820988d1b05f2c322e9bfb432c633e6dbc337e7f05d56126c3a3')
}

ED25519_TEST_PRIVATE = {
    'private_public': bytes.fromhex('d783bfa87ec767c0daf35d64a3eeb591369cab440da8c1c5ddab1756b03ac8ab2751e7d2ba43820988d1b05f2c322e9bfb432c633e6dbc337e7f05d56126c3a3'),
    'public': bytes.fromhex('2751e7d2ba43820988d1b05f2c322e9bfb432c633e6dbc337e7f05d56126c3a3')
}

PRIVATE_TEST_FOOTER = {
    'comment': 'comment'
}

RSA_TEST_HEADER = {
    'key_type': 'ssh-rsa'
}

RSA_TEST_PUBLIC = {
    'e': 65537,
    'n': 22833053504904154459389555875086011925877091961960955705861783493019315221189120363317580685288021091497919773654925550564812490796803771282024780163967422554209751277688842112311576430071315351828702546213848973862817522673806808405949773757009590610580586272025555434425135640999935536685062998675329937670482024388465109442165488688760736271073344883895457879548132789906779877595971745076044768949110090849651020745102646404004325359755499017200188217124698379610854430469218406750035681701070768737312867205567453738732358434468964595741034787407468538158504719157425665152240873255314150689127380129563432352431
}

RSA_TEST_PRIVATE = {
    'd': 12687662076202673191442840781589137377430551565966280481870829752129093525947849249598491475290810749486240511423950192638033118350659977398683131959522126846768337157324786963151359977629538904245630111623506386944202904057433549624173717303340376600477794379790876180714102943959818918160122361761439955141903513046455598694804969967834116707186367556150416819452038707249556775999958762581669020177063675587898653347345482336901143410088427284121327143109415407738336445383809844276198318274273081216177855411348210858605402521346426871130324038611538768699912108553080338858580245272655097723658862898101516632945,
    'e': 65537,
    'iqmp': 12419130393490411154664504416813494900537282233758869183953819910342299114260708527396132668974729868938802898452708601517767672181977384084439195188009597044767142184337119975013653856219597142339113396846772606952275859663855631047289249591295763559595567333065635860785686188030805670201190489445471058341,
    'n': 22833053504904154459389555875086011925877091961960955705861783493019315221189120363317580685288021091497919773654925550564812490796803771282024780163967422554209751277688842112311576430071315351828702546213848973862817522673806808405949773757009590610580586272025555434425135640999935536685062998675329937670482024388465109442165488688760736271073344883895457879548132789906779877595971745076044768949110090849651020745102646404004325359755499017200188217124698379610854430469218406750035681701070768737312867205567453738732358434468964595741034787407468538158504719157425665152240873255314150689127380129563432352431,
    'p': 156859864290944215079044468160464707356176823578818849761827533392313072171894887304379426456356759660669459706418971575856591753051411658256077408456111567225244218205396756138949662433706914228285937950159417816615341515806573676199207625643729598090185637434898215022254811579944390223997250026710246369833,
    'q': 145563389386550331256658220052601337205567145155316924823560913020653409792660282454784694022417441164978649090280981692703017247120232046330237700560786675720114547570992868330030216078165542630930213158707931711434581104578837143742940748317150360990247305951782299025425731762581855379169427745358634109207
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
    public_key = PublicKey(PascalStyleByteStream(public_key_bytes))
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
    private_key = PrivateKey(PascalStyleByteStream(private_key_bytes))
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
    public_key = PublicKey(PascalStyleByteStream(public_key_bytes))
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
    private_key = PrivateKey(PascalStyleByteStream(private_key_bytes))
    if decipher_byte_stream is not None:
        decipher_byte_stream.write(private_key_bytes)
    return private_key_bytes, private_key


def test_public_key():
    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    key = PublicKey(PascalStyleByteStream(public_key_bytes))
    assert key.header == ED25519_TEST_HEADER
    assert isinstance(key.params, Ed25519PublicKeyParams)
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}


def test_public_key_factory():
    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    key = PublicKey.from_bytes(public_key_bytes)
    assert key.header == ED25519_TEST_HEADER
    assert isinstance(key.params, Ed25519PublicKeyParams)
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}
    assert key.bytes == public_key_bytes


def test_public_key_factory_remainder():
    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    remainder = b'\x00'
    public_key_bytes += remainder
    with pytest.warns(UserWarning):
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


def test_private_key():
    private_key_bytes, _ = correct_private_key_bytes_ed25519()
    key = PrivateKey(PascalStyleByteStream(private_key_bytes))
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


def private_key_list_test_assertions(
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
    with pytest.raises(ValueError):
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
    with pytest.raises(ValueError):
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

    private_key_list_test_assertions(
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

    private_key_list_test_assertions(
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

    private_key_list_test_assertions(
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

    with pytest.warns(UserWarning):
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

    with pytest.warns(UserWarning):
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

    with pytest.warns(UserWarning):
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

    with pytest.warns(UserWarning):
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

    with pytest.warns(UserWarning):
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

    with pytest.warns(UserWarning):
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

    with pytest.warns(UserWarning):
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

    with pytest.warns(UserWarning):
        PrivateKeyList.from_bytes(write_byte_stream.getvalue())
