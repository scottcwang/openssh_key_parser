import pytest
from openssh_key.cipher import (AES128_CTRCipher, AES192_CTRCipher,
                                AES256_CTRCipher, NoneCipher, create_cipher)
from openssh_key.kdf_options import KDFOptions


class TestIdentityKDF(KDFOptions):
    def derive_key(self, passphrase, length):
        return bytes(passphrase)

    @classmethod
    def get_options_format_instructions_dict(cls):
        return {}

    @classmethod
    def generate_options(cls, **kwargs):
        return cls({})


def test_factory_none():
    assert create_cipher('none') == NoneCipher


def test_factory_aes128_ctr():
    assert create_cipher('aes128-ctr') == AES128_CTRCipher


def test_factory_aes192_ctr():
    assert create_cipher('aes192-ctr') == AES192_CTRCipher


def test_factory_aes256_ctr():
    assert create_cipher('aes256-ctr') == AES256_CTRCipher


def test_none_encrypt():
    test_bytes = b'abcd'
    assert NoneCipher.encrypt(None, '', test_bytes) == test_bytes


def test_none_decrypt():
    test_bytes = b'abcd'
    assert NoneCipher.decrypt(None, '', test_bytes) == test_bytes


def test_none_block_size():
    assert NoneCipher.BLOCK_SIZE == 8


# RFC3686
TEST_VECTORS = [
    {
        'cls': AES128_CTRCipher,
        'key': bytes.fromhex('AE6852F8121067CC4BF7A5765577F39E'),
        'iv': bytes.fromhex('000000300000000000000000'),
        'plaintext': bytes.fromhex('53696E676C6520626C6F636B206D7367'),
        'ciphertext': bytes.fromhex('E4095D4FB7A7B3792D6175A3261311B8'),
        'block_size': 16,
    },

    {
        'cls': AES128_CTRCipher,
        'key': bytes.fromhex('7E24067817FAE0D743D6CE1F32539163'),
        'iv': bytes.fromhex('006CB6DBC0543B59DA48D90B'),
        'plaintext': bytes.fromhex(
            '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
        ),
        'ciphertext': bytes.fromhex(
            '5104A106168A72D9790D41EE8EDAD388EB2E1EFC46DA57C8FCE630DF9141BE28'
        ),
        'block_size': 16,
    },


    {
        'cls': AES128_CTRCipher,
        'key': bytes.fromhex('7691BE035E5020A8AC6E618529F9A0DC'),
        'iv': bytes.fromhex('00E0017B27777F3F4A1786F0'),
        'plaintext': bytes.fromhex(
            '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223'
        ),
        'ciphertext': bytes.fromhex(
            'C1CF48A89F2FFDD9CF4652E9EFDB72D74540A42BDE6D7836D59A5CEAAEF3105325B2072F'
        ),
        'block_size': 16,
    },

    {
        'cls': AES192_CTRCipher,
        'key': bytes.fromhex(
            '16AF5B145FC9F579C175F93E3BFB0EED863D06CCFDB78515'
        ),
        'iv': bytes.fromhex('0000004836733C147D6D93CB'),
        'plaintext': bytes.fromhex('53696E676C6520626C6F636B206D7367'),
        'ciphertext': bytes.fromhex('4B55384FE259C9C84E7935A003CBE928'),
        'block_size': 16,
    },

    {
        'cls': AES192_CTRCipher,
        'key': bytes.fromhex(
            '7C5CB2401B3DC33C19E7340819E0F69C678C3DB8E6F6A91A'
        ),
        'iv': bytes.fromhex('0096B03B020C6EADC2CB500D'),
        'plaintext': bytes.fromhex(
            '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
        ),
        'ciphertext': bytes.fromhex(
            '453243FC609B23327EDFAAFA7131CD9F8490701C5AD4A79CFC1FE0FF42F4FB00'
        ),
        'block_size': 16,
    },

    {
        'cls': AES192_CTRCipher,
        'key': bytes.fromhex(
            '02BF391EE8ECB159B959617B0965279BF59B60A786D3E0FE'
        ),
        'iv': bytes.fromhex('0007BDFD5CBD60278DCC0912'),
        'plaintext': bytes.fromhex(
            '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223'
        ),
        'ciphertext': bytes.fromhex(
            '96893FC55E5C722F540B7DD1DDF7E758D288BC95C69165884536C811662F2188ABEE0935'
        ),
        'block_size': 16,
    },

    {
        'cls': AES256_CTRCipher,
        'key': bytes.fromhex(
            '776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104'
        ),
        'iv': bytes.fromhex('00000060DB5672C97AA8F0B200000001'),
        'plaintext': bytes.fromhex('53696E676C6520626C6F636B206D7367'),
        'ciphertext': bytes.fromhex('145AD01DBF824EC7560863DC71E3E0C0'),
        'block_size': 16,
    },

    {
        'cls': AES256_CTRCipher,
        'key': bytes.fromhex(
            'F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884'
        ),
        'iv': bytes.fromhex('00FAAC24C1585EF15A43D87500000001'),
        'plaintext': bytes.fromhex(
            '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
        ),
        'ciphertext': bytes.fromhex(
            'F05E231B3894612C49EE000B804EB2A9B8306B508F839D6A5530831D9344AF1C'
        ),
        'block_size': 16,
    },

    {
        'cls': AES256_CTRCipher,
        'key': bytes.fromhex(
            'FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D'
        ),
        'iv': bytes.fromhex('001CC5B751A51D70A1C1114800000001'),
        'plaintext': bytes.fromhex(
            '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
            '20212223'
        ),
        'ciphertext': bytes.fromhex(
            'EB6C52821D0BBBF7CE7594462ACA4FAAB407DF866569FD07F48CC0B583D6071F'
            '1EC0E6B8'
        ),
        'block_size': 16,
    }
]


@pytest.mark.parametrize('test_case', TEST_VECTORS)
def test_encrypt(test_case):
    return test_case['cls'].encrypt(
        TestIdentityKDF(),
        test_case['key']
        + test_case['iv'],
        test_case['plaintext']
    ) == test_case['ciphertext']


@pytest.mark.parametrize('test_case', TEST_VECTORS)
def test_decrypt(test_case):
    return test_case['cls'].decrypt(
        TestIdentityKDF(),
        test_case['key']
        + test_case['iv'],
        test_case['ciphertext']
    ) == test_case['plaintext']


@pytest.mark.parametrize('test_case', TEST_VECTORS)
def test_block_size(test_case):
    assert test_case['cls'].BLOCK_SIZE == test_case['block_size']
