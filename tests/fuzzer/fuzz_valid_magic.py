#!/usr/bin/env python3.10

import atheris
import sys, re
from base64 import b64encode

with atheris.instrument_imports():
    #import openssh_key
    from openssh_key.private_key_list import PrivateKeyList

@atheris.instrument_func
def TestOneInput(data):
    headered_data = bytes("openssh-key-v1", 'utf-8')
    b = bytes("-----BEGIN OPENSSH PRIVATE KEY-----\n", 'utf-8')  \
        + re.sub(b"(.{70})", b"\\1\n", b64encode(headered_data), 0, re.DOTALL) \
        + bytes("\n-----END OPENSSH PRIVATE KEY-----\n", 'utf-8')
    key = b.decode("utf-8")
    try:
        parsed = PrivateKeyList.from_string(key, None)
    except ValueError as e:
        if not e.args[0] == "Unexpected error condition reached.":
            pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
