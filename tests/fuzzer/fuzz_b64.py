#!/usr/bin/env python3.10

import atheris,sys
import sys
with atheris.instrument_imports():
    #import openssh_key
    from openssh_key.private_key_list import PrivateKeyList

@atheris.instrument_func
def TestOneInput(data):
    key = bytes("-----BEGIN OPENSSH PRIVATE KEY-----\nopenssh-key-v1", 'utf-8')  \
        + data \
        + bytes("\n-----END OPENSSH PRIVATE KEY-----\n", 'utf-8')
    try:
        parsed = PrivateKeyList.from_string(key, None)
    except ValueError as e:
        if e.args[0] == "Not an openssh private key":
            pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
