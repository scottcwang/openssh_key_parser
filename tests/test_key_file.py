import base64

import openssh_key.key_file as kf
from tests.test_key_list import (
    PublicKey,
    PrivateKey,
    PublicPrivateKeyPair,
    PrivateKeyList,
    ED25519_TEST_HEADER,
    ED25519_TEST_PUBLIC,
    ED25519_TEST_PRIVATE,
    PRIVATE_TEST_FOOTER
)

PUBLIC_KEY_TEST = PublicKey(
    ED25519_TEST_HEADER,
    ED25519_TEST_PUBLIC,
    {}
)

PRIVATE_KEYS_TEST = PrivateKeyList.from_list(
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
    ]
)


def test_parse_key_container_private():
    private_keys_bytes = PRIVATE_KEYS_TEST.pack()
    private_keys_b64 = base64.b64encode(private_keys_bytes).decode()
    private_keys_wrapped = ''.join([
        (
            private_keys_b64[
                i:min(i + kf.WRAP_COL, len(private_keys_b64))
            ] + '\n'
        )
        for i in range(0, len(private_keys_b64), kf.WRAP_COL)
    ])
    private_keys_string = kf.OPENSSH_PRIVATE_KEY_HEADER + '\n' + \
        private_keys_wrapped + '\n' + \
        kf.OPENSSH_PRIVATE_KEY_FOOTER
    assert kf.parse_key_container(private_keys_string) == PRIVATE_KEYS_TEST


def test_parse_key_container_public_one_key():
    comment = 'comment'
    public_key_bytes = PUBLIC_KEY_TEST.pack_public()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string = PUBLIC_KEY_TEST.header['key_type'] + ' ' + \
        public_key_b64 + ' ' + \
        comment
    key_container = kf.parse_key_container(public_key_string)
    assert key_container[0] == PUBLIC_KEY_TEST
    assert key_container[0].key_type_clear == \
        PUBLIC_KEY_TEST.header['key_type']
    assert key_container[0].comment_clear == comment
