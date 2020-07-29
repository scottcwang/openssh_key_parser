import base64

import pytest

import openssh_key.key_file as kf
from tests.test_key_list import (
    PublicKey,
    PrivateKey,
    PublicPrivateKeyPair,
    PrivateKeyList,
    ED25519_TEST_HEADER,
    ED25519_TEST_PUBLIC,
    ED25519_TEST_PRIVATE,
    PRIVATE_TEST_FOOTER,
    RSA_TEST_HEADER,
    RSA_TEST_PUBLIC
)

PUBLIC_KEY_TEST = [
    PublicKey(
        ED25519_TEST_HEADER,
        ED25519_TEST_PUBLIC,
        {}
    ),
    PublicKey(
        RSA_TEST_HEADER,
        RSA_TEST_PUBLIC,
        {}
    )
]

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
    public_key_bytes = PUBLIC_KEY_TEST[0].pack_public()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string = PUBLIC_KEY_TEST[0].header['key_type'] + ' ' + \
        public_key_b64 + ' ' + \
        comment + '\n'
    key_container = kf.parse_key_container(public_key_string)
    assert key_container[0] == PUBLIC_KEY_TEST[0]
    assert key_container[0].key_type_clear == \
        PUBLIC_KEY_TEST[0].header['key_type']
    assert key_container[0].comment_clear == comment


def test_parse_key_container_public_two_keys():
    public_key_string = ''

    for i, public_key in enumerate(PUBLIC_KEY_TEST):
        comment = f'comment_{i}'
        public_key_bytes = public_key.pack_public()
        public_key_b64 = base64.b64encode(public_key_bytes).decode()
        public_key_string += public_key.header['key_type'] + ' ' + \
            public_key_b64 + ' ' + \
            comment + '\n'

    key_container = kf.parse_key_container(public_key_string)

    for i, public_key_parsed in enumerate(key_container):
        assert key_container[i] == public_key_parsed
        assert key_container[i].key_type_clear == \
            public_key_parsed.header['key_type']
        assert key_container[i].comment_clear == f'comment_{i}'


def test_parse_key_container_public_inconsistent_key_type():
    comment = 'comment'
    public_key_bytes = PUBLIC_KEY_TEST[0].pack_public()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string = 'ssh-rsa ' + \
        public_key_b64 + ' ' + \
        comment + '\n'
    with pytest.warns(
        UserWarning,
        match='Inconsistency between clear and encoded key types for key 0'
    ):
        key_container = kf.parse_key_container(public_key_string)
    assert key_container[0] == PUBLIC_KEY_TEST[0]
    assert key_container[0].key_type_clear == 'ssh-rsa'
    assert key_container[0].comment_clear == comment


def test_parse_key_container_public_not_a_key_1():
    comment = 'comment'
    public_key_bytes = PUBLIC_KEY_TEST[0].pack_public()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string = PUBLIC_KEY_TEST[0].header['key_type'] + ' ' + \
        public_key_b64 + ' ' + \
        comment + '\n'
    public_key_string += 'random'
    with pytest.warns(
        UserWarning,
        match='Could not parse line 1; skipping'
    ):
        key_container = kf.parse_key_container(public_key_string)
    assert key_container[0] == PUBLIC_KEY_TEST[0]
    assert key_container[0].key_type_clear == \
        PUBLIC_KEY_TEST[0].header['key_type']
    assert key_container[0].comment_clear == comment
    assert len(key_container) == 1


def test_parse_key_container_public_not_a_key_2():
    public_key_string = 'not a key\n'
    comment = 'comment'
    public_key_bytes = PUBLIC_KEY_TEST[0].pack_public()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    public_key_string += PUBLIC_KEY_TEST[0].header['key_type'] + ' ' + \
        public_key_b64 + ' ' + \
        comment + '\n'
    with pytest.warns(
        UserWarning,
        match='Could not parse line 0; skipping'
    ):
        key_container = kf.parse_key_container(public_key_string)

    print(key_container)
    assert key_container[0] == PUBLIC_KEY_TEST[0]
    assert key_container[0].key_type_clear == \
        PUBLIC_KEY_TEST[0].header['key_type']
    assert key_container[0].comment_clear == comment
    assert len(key_container) == 1
