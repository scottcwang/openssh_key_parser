import base64
import warnings

from openssh_key.key_list import (
    PublicKey,
    PrivateKeyList
)

OPENSSH_PRIVATE_KEY_HEADER = '-----BEGIN OPENSSH PRIVATE KEY-----'
OPENSSH_PRIVATE_KEY_FOOTER = '-----END OPENSSH PRIVATE KEY-----'

WRAP_COL = 70


def parse_key_container(key_container):
    key_lines = key_container.splitlines()

    if key_lines[0] == OPENSSH_PRIVATE_KEY_HEADER and \
            key_lines[-1] == OPENSSH_PRIVATE_KEY_FOOTER:
        key_b64 = ''.join(key_lines[1:-1])
        key_bytes = base64.b64decode(key_b64)
        return PrivateKeyList.from_bytes(key_bytes)

    else:
        keys = []
        for i, key_line in enumerate(key_lines):
            key_type_clear, key_b64, comment_clear = key_line.split(
                ' ',
                maxsplit=2
            )
            key_bytes = base64.b64decode(key_b64)
            public_key = PublicKey.from_bytes(key_bytes)
            public_key.key_type_clear = key_type_clear
            public_key.comment_clear = comment_clear
            if public_key.header['key_type'] != key_type_clear:
                warnings.warn(
                    f'Inconsistency between clear and encoded '
                    f'key types for key {i}'
                )
            keys.append(public_key)
        return keys
