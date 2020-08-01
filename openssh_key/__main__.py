#!/usr/bin/env python3

if __name__ == "__main__":
    import argparse
    import warnings
    import json

    from openssh_key.private_key_list import (
        OPENSSH_PRIVATE_KEY_HEADER,
        PrivateKeyList
    )
    from openssh_key.key import (
        PublicKey
    )

    JSON_INDENT = 4

    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    args = parser.parse_args()

    file_contents = open(args.filename).read()

    if file_contents.startswith(OPENSSH_PRIVATE_KEY_HEADER):
        parsed_contents = PrivateKeyList.from_string(file_contents)
    else:
        parsed_contents = []
        for i, file_line in enumerate(file_contents.splitlines()):
            try:
                parsed_contents.append(PublicKey.from_string(file_line))
            except:
                warnings.warn(f'Could not parse line {i}')

    class KeyJSONEncoder(json.JSONEncoder):
        def default(self, o):
            if hasattr(o, '__dict__'):
                return o.__dict__
            if hasattr(o, '__str__'):
                return str(o)
            else:
                return super().default(o)

    print(KeyJSONEncoder(indent=JSON_INDENT).encode(parsed_contents))
