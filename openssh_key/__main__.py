#!/usr/bin/env python3

if __name__ == "__main__":
    import argparse
    import json
    import typing
    import warnings

    from openssh_key.key import PublicKey
    from openssh_key.private_key_list import PrivateKeyList

    JSON_INDENT = 4

    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    parser.add_argument('--passphrase')
    args = parser.parse_args()

    with open(args.filename, encoding='utf8') as f:
        file_contents = f.read()

        parsed_contents: typing.Union[PrivateKeyList, typing.List[PublicKey]]
        if file_contents.startswith(PrivateKeyList.OPENSSH_PRIVATE_KEY_HEADER):
            parsed_contents = PrivateKeyList.from_string(
                file_contents,
                args.passphrase
            )
        else:
            parsed_contents = []
            for i, file_line in enumerate(file_contents.splitlines()):
                try:
                    parsed_contents.append(PublicKey.from_string(file_line))
                except (ValueError, NotImplementedError, EOFError):
                    warnings.warn(f'Could not parse line {i}')

        class KeyJSONEncoder(json.JSONEncoder):
            def default(self, o: object) -> typing.Any:
                if hasattr(o, '__dict__'):
                    return o.__dict__
                if hasattr(o, '__str__'):
                    return str(o)
                else:
                    return super().default(o)

        print(KeyJSONEncoder(indent=JSON_INDENT).encode(parsed_contents))
