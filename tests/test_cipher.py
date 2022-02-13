import pytest
from openssh_key.cipher import (AES128_CBCCipher, AES128_CTRCipher,
                                AES128_GCMCipher, AES192_CBCCipher,
                                AES192_CTRCipher, AES256_CBCCipher,
                                AES256_CTRCipher, AES256_GCMCipher,
                                ChaCha20Poly1305Cipher, NoneCipher,
                                TripleDES_CBCCipher, get_cipher_class)
from openssh_key.kdf_options import KDFOptions


class TestIdentityKDF(KDFOptions):
    def derive_key(self, passphrase, length):
        return bytes(passphrase)

    @classmethod
    def get_format_instructions_dict(cls):
        return {}

    @classmethod
    def generate_options(cls, **kwargs):
        return cls({})


def test_factory_none():
    assert get_cipher_class('none') == NoneCipher


def test_factory_aes128_ctr():
    assert get_cipher_class('aes128-ctr') == AES128_CTRCipher


def test_factory_aes192_ctr():
    assert get_cipher_class('aes192-ctr') == AES192_CTRCipher


def test_factory_aes256_ctr():
    assert get_cipher_class('aes256-ctr') == AES256_CTRCipher


def test_none_encrypt():
    test_bytes = b'abcd'
    assert NoneCipher.encrypt(None, '', test_bytes) == test_bytes


def test_none_decrypt():
    test_bytes = b'abcd'
    assert NoneCipher.decrypt(None, '', test_bytes) == test_bytes


def test_none_block_size():
    assert NoneCipher.BLOCK_SIZE == 8


TEST_VECTORS = [
    # Selected from the TCBCvartext.rsp and TCBCvarkey.rsp test data
    # https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#TDES
    {
        'cls': TripleDES_CBCCipher,
        'key': bytes.fromhex(
            '010101010101010101010101010101010101010101010101'
        ),
        'iv': bytes.fromhex('0000000000000000'),
        'plaintext': bytes.fromhex('8000000000000000'),
        'ciphertext': bytes.fromhex('95f8a5e5dd31d900'),
        'block_size': 8,
    },

    {
        'cls': TripleDES_CBCCipher,
        'key': bytes.fromhex(
            '800101010101010180010101010101018001010101010101'
        ),
        'iv': bytes.fromhex('0000000000000000'),
        'plaintext': bytes.fromhex('0000000000000000'),
        'ciphertext': bytes.fromhex('95a8d72813daa94d'),
        'block_size': 8,
    },

    # RFC3686
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
    },

    # Selected from the CBCGFSbox*.rsp test data
    # https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES

    {
        'cls': AES128_CBCCipher,
        'key': bytes.fromhex('00000000000000000000000000000000'),
        'iv': bytes.fromhex('00000000000000000000000000000000'),
        'plaintext': bytes.fromhex('f34481ec3cc627bacd5dc3fb08f273e6'),
        'ciphertext': bytes.fromhex('0336763e966d92595a567cc9ce537f5e'),
        'block_size': 16,
    },

    {
        'cls': AES192_CBCCipher,
        'key': bytes.fromhex('000000000000000000000000000000000000000000000000'),
        'iv': bytes.fromhex('00000000000000000000000000000000'),
        'plaintext': bytes.fromhex('1b077a6af4b7f98229de786d7516b639'),
        'ciphertext': bytes.fromhex('275cfc0413d8ccb70513c3859b1d0f72'),
        'block_size': 16,
    },

    {
        'cls': AES256_CBCCipher,
        'key': bytes.fromhex(
            '0000000000000000000000000000000000000000000000000000000000000000'
        ),
        'iv': bytes.fromhex('00000000000000000000000000000000'),
        'plaintext': bytes.fromhex('014730f80ac625fe84f026c60bfd547d'),
        'ciphertext': bytes.fromhex('5c9d844ed46f9885085e5d6a4f94c7d7'),
        'block_size': 16,
    },

    # Selected from
    # https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf

    {
        'cls': AES128_GCMCipher,
        'key': bytes.fromhex('00000000000000000000000000000000'),
        'iv': bytes.fromhex('000000000000000000000000'),
        'plaintext': bytes.fromhex('00000000000000000000000000000000'),
        'ciphertext': bytes.fromhex(
            '0388dace60b6a392f328c2b971b2fe78'
            + 'ab6e47d42cec13bdf53a67b21257bddf'
        ),
        'block_size': 16,
    },

    {
        'cls': AES128_GCMCipher,
        'key': bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
        'iv': bytes.fromhex('cafebabefacedbaddecaf888'),
        'plaintext': bytes.fromhex(
            'd9313225f88406e5a55909c5aff5269a'
            + '86a7a9531534f7da2e4c303d8a318a72'
            + '1c3c0c95956809532fcf0e2449a6b525'
            + 'b16aedf5aa0de657ba637b391aafd255'
        ),
        'ciphertext': bytes.fromhex(
            '42831ec2217774244b7221b784d0d49c'
            + 'e3aa212f2c02a4e035c17e2329aca12e'
            + '21d514b25466931c7d8f6a5aac84aa05'
            + '1ba30b396a0aac973d58e091473f5985'
            + '4d5c2af327cd64a62cf35abd2ba6fab4'
        ),
        'block_size': 16,
    },

    {
        'cls': AES256_GCMCipher,
        'key': bytes.fromhex(
            '0000000000000000000000000000000000000000000000000000000000000000'
        ),
        'iv': bytes.fromhex('000000000000000000000000'),
        'plaintext': bytes.fromhex('00000000000000000000000000000000'),
        'ciphertext': bytes.fromhex(
            'cea7403d4d606b6e074ec5d3baf39d18'
            + 'd0d1c8a799996bf0265b98b5d48ab919'
        ),
        'block_size': 16,
    },

    {
        'cls': AES256_GCMCipher,
        'key': bytes.fromhex(
            'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'
        ),
        'iv': bytes.fromhex('cafebabefacedbaddecaf888'),
        'plaintext': bytes.fromhex(
            'd9313225f88406e5a55909c5aff5269a'
            + '86a7a9531534f7da2e4c303d8a318a72'
            + '1c3c0c95956809532fcf0e2449a6b525'
            + 'b16aedf5aa0de657ba637b391aafd255'
        ),
        'ciphertext': bytes.fromhex(
            '522dc1f099567d07f47f37a32a84427d'
            + '643a8cdcbfe5c0c97598a2bd2555d1aa'
            + '8cb08e48590dbb3da7b08b1056828838'
            + 'c5f61e6393ba7a0abcc9f662898015ad'
            + 'b094dac5d93471bdec1a502270e3cc6c'
        ),
        'block_size': 16,
    },

    {
        'cls': ChaCha20Poly1305Cipher,
        'key': bytes.fromhex(
            '00000000000000000000000000000000'
            + '00000000000000000000000000000000'
        ),
        'iv': bytes(),  # ChaCha20Poly1305 does not use the IV from the KDF
        'plaintext': bytes.fromhex(
            '00000000000000000000000000000000'
            + '00000000000000000000000000000000'
            + '00000000000000000000000000000000'
            + '00000000000000000000000000000000'
        ),
        'ciphertext': bytes.fromhex(
            # RFC 8439
            # Appendix A.1, test vector #2
            # Block counter 1
            '9f07e7be5551387a98ba977c732d080d'
            + 'cb0f29a048e3656912c6533e32ee7aed'
            + '29b721769ce64e43d57133b074d839d5'
            + '31ed1f28510afb45ace10a1f4b794d6f'
            # Appendix A.4, test vector #1
            # The Poly1305 tag key's first 32 keystream bytes are
            # '76b8e0ada0f13d90405d6ae55386bd28'
            # + 'bdd219b8a08ded1aa836efcc8b770dc7'
            # Apply Poly1305 to the ciphertext to obtain the tag:
            + 'd15fcdffe28f9464d4d1918ae720e2e9'
        ),
        'block_size': 8,
    },
]


@pytest.mark.parametrize('test_case', TEST_VECTORS)
def test_encrypt(test_case):
    return test_case['cls'].encrypt(
        TestIdentityKDF(None),
        test_case['key']
        + test_case['iv'],
        test_case['plaintext']
    ) == test_case['ciphertext']


@pytest.mark.parametrize('test_case', TEST_VECTORS)
def test_decrypt(test_case):
    return test_case['cls'].decrypt(
        TestIdentityKDF(None),
        test_case['key']
        + test_case['iv'],
        test_case['ciphertext']
    ) == test_case['plaintext']


@pytest.mark.parametrize('test_case', TEST_VECTORS)
def test_block_size(test_case):
    assert test_case['cls'].BLOCK_SIZE == test_case['block_size']
