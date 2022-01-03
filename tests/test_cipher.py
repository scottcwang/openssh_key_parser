from openssh_key.cipher import AES256_CTRCipher, NoneCipher, create_cipher
from openssh_key.kdf import KDFResult


def test_factory_none():
    assert create_cipher('none') == NoneCipher


def test_factory_aes256_ctr():
    assert create_cipher('aes256-ctr') == AES256_CTRCipher


def test_none_encrypt():
    test_bytes = b'abcd'
    assert NoneCipher.encrypt(None, test_bytes) == test_bytes


def test_none_decrypt():
    test_bytes = b'abcd'
    assert NoneCipher.decrypt(None, test_bytes) == test_bytes


def test_none_block_size():
    assert NoneCipher.BLOCK_SIZE == 8


# RFC 3686
AES256_CTR_TEST_VECTORS = [
    {
        'key': bytes.fromhex(
            '776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104'
        ),
        'iv': bytes.fromhex('00000060DB5672C97AA8F0B200000001'),
        'plaintext': bytes.fromhex('53696E676C6520626C6F636B206D7367'),
        'ciphertext': bytes.fromhex('145AD01DBF824EC7560863DC71E3E0C0')
    },

    {
        'key': bytes.fromhex(
            'F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884'
        ),
        'iv': bytes.fromhex('00FAAC24C1585EF15A43D87500000001'),
        'plaintext': bytes.fromhex(
            '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
        ),
        'ciphertext': bytes.fromhex(
            'F05E231B3894612C49EE000B804EB2A9B8306B508F839D6A5530831D9344AF1C'
        )
    },

    {
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
        )
    }
]


def aes256_ctr_encrypt(i):
    return AES256_CTRCipher.encrypt(
        KDFResult(
            AES256_CTR_TEST_VECTORS[i]['key'],
            AES256_CTR_TEST_VECTORS[i]['iv']
        ),
        AES256_CTR_TEST_VECTORS[i]['plaintext']
    ) == AES256_CTR_TEST_VECTORS[i]['ciphertext']


def aes256_ctr_decrypt(i):
    return AES256_CTRCipher.decrypt(
        KDFResult(
            AES256_CTR_TEST_VECTORS[i]['key'],
            AES256_CTR_TEST_VECTORS[i]['iv']
        ),
        AES256_CTR_TEST_VECTORS[i]['ciphertext']
    ) == AES256_CTR_TEST_VECTORS[i]['plaintext']


def test_aes256_ctr_encrypt_0():
    assert aes256_ctr_encrypt(0)


def test_aes256_ctr_decrypt_0():
    assert aes256_ctr_decrypt(0)


def test_aes256_ctr_encrypt_1():
    assert aes256_ctr_encrypt(1)


def test_aes256_ctr_decrypt_1():
    assert aes256_ctr_decrypt(1)


def test_aes256_ctr_encrypt_2():
    assert aes256_ctr_encrypt(2)


def test_aes256_ctr_decrypt_2():
    assert aes256_ctr_decrypt(2)


def test_aes256_ctr_block_size():
    assert AES256_CTRCipher.BLOCK_SIZE == 16
