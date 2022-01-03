import base64

import pytest
from openssh_key.key import PrivateKey, PublicKey
from openssh_key.key_params import (Ed25519PrivateKeyParams,
                                    Ed25519PublicKeyParams,
                                    RSAPrivateKeyParams, RSAPublicKeyParams)
from openssh_key.pascal_style_byte_stream import (PascalStyleByteStream,
                                                  PascalStyleFormatInstruction)


def test_public_key_header_format_instructions_dict():
    assert PublicKey.HEADER_FORMAT_INSTRUCTIONS_DICT == {
        'key_type': PascalStyleFormatInstruction.STRING
    }


def test_public_key_footer_format_instructions_dict():
    assert PublicKey.FOOTER_FORMAT_INSTRUCTIONS_DICT == {}


def test_private_key_header_format_instructions_dict():
    assert PrivateKey.HEADER_FORMAT_INSTRUCTIONS_DICT == {
        'key_type': PascalStyleFormatInstruction.STRING
    }


def test_private_key_footer_format_instructions_dict():
    assert PrivateKey.FOOTER_FORMAT_INSTRUCTIONS_DICT == {
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


def correct_public_key_bytes_ed25519(write_byte_stream=None):
    public_key_write_byte_stream = PascalStyleByteStream()
    public_key_write_byte_stream.write_from_format_instructions_dict(
        PublicKey.HEADER_FORMAT_INSTRUCTIONS_DICT,
        ED25519_TEST_HEADER
    )
    public_key_write_byte_stream.write_from_format_instructions_dict(
        Ed25519PublicKeyParams.FORMAT_INSTRUCTIONS_DICT,
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
        PrivateKey.HEADER_FORMAT_INSTRUCTIONS_DICT,
        ED25519_TEST_HEADER
    )
    private_key_write_byte_stream.write_from_format_instructions_dict(
        Ed25519PrivateKeyParams.FORMAT_INSTRUCTIONS_DICT,
        ED25519_TEST_PRIVATE
    )
    private_key_write_byte_stream.write_from_format_instructions_dict(
        PrivateKey.FOOTER_FORMAT_INSTRUCTIONS_DICT,
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
        PublicKey.HEADER_FORMAT_INSTRUCTIONS_DICT,
        RSA_TEST_HEADER
    )
    public_key_write_byte_stream.write_from_format_instructions_dict(
        RSAPublicKeyParams.FORMAT_INSTRUCTIONS_DICT,
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
        PrivateKey.HEADER_FORMAT_INSTRUCTIONS_DICT,
        RSA_TEST_HEADER
    )
    private_key_write_byte_stream.write_from_format_instructions_dict(
        RSAPrivateKeyParams.FORMAT_INSTRUCTIONS_DICT,
        RSA_TEST_PRIVATE
    )
    private_key_write_byte_stream.write_from_format_instructions_dict(
        PrivateKey.FOOTER_FORMAT_INSTRUCTIONS_DICT,
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
    assert type(key.params) == Ed25519PublicKeyParams
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}


def test_public_key_from_bytes():
    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    key = PublicKey.from_bytes(public_key_bytes)
    assert key.header == ED25519_TEST_HEADER
    assert type(key.params) == Ed25519PublicKeyParams
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}


def test_public_key_from_bytes_remainder():
    public_key_bytes, _ = correct_public_key_bytes_ed25519()
    remainder = b'\x00'
    public_key_bytes += remainder
    with pytest.warns(UserWarning, match='Excess bytes in key'):
        key = PublicKey.from_bytes(public_key_bytes)
    assert key.header == ED25519_TEST_HEADER
    assert type(key.params) == Ed25519PublicKeyParams
    assert key.params == ED25519_TEST_PUBLIC
    assert key.footer == {}
    assert key.clear == {'remainder': remainder}


PUBLIC_KEY_TEST = PublicKey(
    ED25519_TEST_HEADER,
    ED25519_TEST_PUBLIC,
    {}
)


def test_public_key_from_string():
    comment = 'comment with multiple words'
    public_key_bytes = PUBLIC_KEY_TEST.pack_public_bytes()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string = PUBLIC_KEY_TEST.header['key_type'] + ' ' + \
        public_key_b64 + ' ' + \
        comment
    public_key = PublicKey.from_string(public_key_string)
    assert public_key.__dict__ == {
        **PUBLIC_KEY_TEST.__dict__,
        'clear': {
            'key_type': PUBLIC_KEY_TEST.header['key_type'],
            'comment': comment
        }
    }


def test_public_key_from_string_inconsistent_key_type():
    comment = 'comment'
    public_key_bytes = PUBLIC_KEY_TEST.pack_public_bytes()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string = 'ssh-rsa ' + \
        public_key_b64 + ' ' + \
        comment
    with pytest.warns(
        UserWarning,
        match='Inconsistency between clear and encoded key types'
    ):
        public_key = PublicKey.from_string(public_key_string)
    assert public_key.__dict__ == {
        **PUBLIC_KEY_TEST.__dict__,
        'clear': {
            'key_type': 'ssh-rsa',
            'comment': comment
        }
    }


def test_public_key_from_string_not_a_key():
    with pytest.raises(ValueError):
        PublicKey.from_string('insufficient tokens')


def test_public_key_pack_public_bytes():
    _, public_key = correct_public_key_bytes_ed25519()
    public_key_bytes = public_key.pack_public_bytes()
    public_key_byte_stream = PascalStyleByteStream(public_key_bytes)
    assert public_key_byte_stream.read_from_format_instructions_dict(
        PublicKey.HEADER_FORMAT_INSTRUCTIONS_DICT
    ) == ED25519_TEST_HEADER
    assert public_key_byte_stream.read_from_format_instructions_dict(
        Ed25519PublicKeyParams.FORMAT_INSTRUCTIONS_DICT
    ) == ED25519_TEST_PUBLIC
    assert public_key_byte_stream.read_from_format_instructions_dict(
        PublicKey.FOOTER_FORMAT_INSTRUCTIONS_DICT
    ) == {}


def test_public_key_pack_public_string():
    _, public_key = correct_public_key_bytes_ed25519()
    public_key_string = public_key.pack_public_string()
    assert public_key_string == (
        public_key.header['key_type'] + ' ' +
        base64.b64encode(public_key.pack_public_bytes()).decode() + '\n'
    )


def test_public_key_pack_public_string_clear_comment():
    comment = 'comment with multiple words'
    public_key_bytes = PUBLIC_KEY_TEST.pack_public_bytes()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string = PUBLIC_KEY_TEST.header['key_type'] + ' ' + \
        public_key_b64 + ' ' + \
        comment
    public_key = PublicKey.from_string(public_key_string)
    public_key_string = public_key.pack_public_string(use_clear_comment=True)
    assert public_key_string == (
        public_key.header['key_type'] + ' ' +
        base64.b64encode(public_key.pack_public_bytes()).decode() + ' ' +
        comment + '\n'
    )


def test_public_key_pack_public_string_no_clear_comment():
    comment = 'comment with multiple words'
    public_key_bytes = PUBLIC_KEY_TEST.pack_public_bytes()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string = PUBLIC_KEY_TEST.header['key_type'] + ' ' + \
        public_key_b64 + ' ' + \
        comment
    public_key = PublicKey.from_string(public_key_string)
    public_key_string = public_key.pack_public_string(use_clear_comment=False)
    assert public_key_string == (
        public_key.header['key_type'] + ' ' +
        base64.b64encode(public_key.pack_public_bytes()).decode() + '\n'
    )


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
    assert type(key.params) == Ed25519PrivateKeyParams
    assert key.footer == PRIVATE_TEST_FOOTER


def test_private_key_from_bytes():
    private_key_bytes, _ = correct_private_key_bytes_ed25519()
    key = PrivateKey.from_bytes(private_key_bytes)
    assert key.header == ED25519_TEST_HEADER
    assert key.params == ED25519_TEST_PRIVATE
    assert type(key.params) == Ed25519PrivateKeyParams
    assert key.footer == PRIVATE_TEST_FOOTER


def test_private_key_pack_public():
    _, private_key = correct_private_key_bytes_ed25519()
    public_key_bytes = private_key.pack_public_bytes()
    public_key_byte_stream = PascalStyleByteStream(public_key_bytes)
    assert public_key_byte_stream.read_from_format_instructions_dict(
        PublicKey.HEADER_FORMAT_INSTRUCTIONS_DICT
    ) == ED25519_TEST_HEADER
    assert public_key_byte_stream.read_from_format_instructions_dict(
        Ed25519PublicKeyParams.FORMAT_INSTRUCTIONS_DICT
    ) == ED25519_TEST_PUBLIC
    assert public_key_byte_stream.read_from_format_instructions_dict(
        PublicKey.FOOTER_FORMAT_INSTRUCTIONS_DICT
    ) == {}


def test_private_key_pack_private_bytes():
    _, private_key = correct_private_key_bytes_ed25519()
    private_key_bytes = private_key.pack_private_bytes()
    private_key_byte_stream = PascalStyleByteStream(private_key_bytes)
    assert private_key_byte_stream.read_from_format_instructions_dict(
        PrivateKey.HEADER_FORMAT_INSTRUCTIONS_DICT
    ) == ED25519_TEST_HEADER
    assert private_key_byte_stream.read_from_format_instructions_dict(
        Ed25519PrivateKeyParams.FORMAT_INSTRUCTIONS_DICT
    ) == ED25519_TEST_PRIVATE
    assert private_key_byte_stream.read_from_format_instructions_dict(
        PrivateKey.FOOTER_FORMAT_INSTRUCTIONS_DICT
    ) == PRIVATE_TEST_FOOTER


def test_private_key_pack_public_string():
    _, private_key = correct_private_key_bytes_ed25519()
    public_key_string = private_key.pack_public_string()
    assert public_key_string == (
        private_key.header['key_type'] + ' ' +
        base64.b64encode(private_key.pack_public_bytes()).decode() + ' ' +
        private_key.footer['comment'] + '\n'
    )


def test_private_key_pack_public_string_footer_comment():
    _, private_key = correct_private_key_bytes_ed25519()
    public_key_string = private_key.pack_public_string(
        use_footer_comment=True
    )
    assert public_key_string == (
        private_key.header['key_type'] + ' ' +
        base64.b64encode(private_key.pack_public_bytes()).decode() + ' ' +
        private_key.footer['comment'] + '\n'
    )


def test_private_key_pack_public_string_no_footer_comment():
    _, private_key = correct_private_key_bytes_ed25519()
    public_key_string = private_key.pack_public_string(
        use_footer_comment=False
    )
    assert public_key_string == (
        private_key.header['key_type'] + ' ' +
        base64.b64encode(private_key.pack_public_bytes()).decode() + '\n'
    )
