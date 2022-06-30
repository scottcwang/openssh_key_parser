# openssh_key_parser

This repository provides `openssh_key`, a Python package providing utilities to
parse and pack OpenSSH private and public key files.

It supports parsing and packing keys of all types currently supported by
OpenSSH:

* `ssh-rsa`
* `ssh-ed25519`
* `ssh-dss`
* `ecdsa-sha2-{nistp256,nistp384,nistp521}`
* `sk-{ed25519,ecdsa-sha2-nistp256}@openssh.com` FIDO/U2F security keys
* `*-cert-v01@openssh.com` certificates

It can optionally encrypt and decrypt private keys using the `bcrypt` key
derivation function and any cipher currently supported by OpenSSH:

* `aes{128,192,256}-{ctr,cbc}`
* `aes{128,256}-gcm@openssh.com`
* `chacha20-poly1305@openssh.com`
* `3des-cbc`

It is compliant with
the [OpenSSH private key vendor extension](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD),
in particular supporting multiple keys in a private key file.

Keys can be converted to corresponding classes provided by:
* [`cryptography`](https://pypi.org/project/cryptography/)
* [`pynacl`](https://pypi.org/project/PyNaCl/)

Check out the [documentation](https://openssh-key-parser.readthedocs.io/en/latest/).

## Example

### See what is in an OpenSSH key file

```
$ ssh-keygen -t ed25519 -N secret_passphrase -C my_comment -f test_id_ed25519
Generating public/private ed25519 key pair.
Your identification has been saved in test_id_ed25519.
Your public key has been saved in test_id_ed25519.pub.
The key fingerprint is:
SHA256:NbhmjL1RfNkYWOb63Rq2ugIzsmr9zLoSsn5ZUPa3Qic my_comment
The key's randomart image is:
+--[ED25519 256]--+
|           o+    |
|      o  o.o =   |
|     o .. = = .  |
|    .  +E+o+     |
|     ...S+..     |
|  . . oo=o.. . . |
|   o = o.=  . + .|
|  . = oo  .  . + |
| ..o.oo++  .ooo  |
+----[SHA256]-----+
```
```
$ python -m openssh_key test_id_ed25519 --passphrase secret_passphrase
```
```json
{
    "data": [
        [
            {
                "header": {
                    "key_type": "ssh-ed25519"
                },
                "params": {
                    "data": {
                        "public": "b'\\xd0\\x96\\x7f\\xcd\\x02K\\x8e\\xfe)\\xc1\\xd1p\\x00\\xbd\\xcf\\xe3\\xf6\\xe8\\x91\\xc9\\x84\\xf5\\x9e\\xacL\\xe0\\x9c/2i8R'"
                    }
                },
                "footer": {},
                "clear": {}
            },
            {
                "header": {
                    "key_type": "ssh-ed25519"
                },
                "params": {
                    "data": {
                        "public": "b'\\xd0\\x96\\x7f\\xcd\\x02K\\x8e\\xfe)\\xc1\\xd1p\\x00\\xbd\\xcf\\xe3\\xf6\\xe8\\x91\\xc9\\x84\\xf5\\x9e\\xacL\\xe0\\x9c/2i8R'",
                        "private_public": "b'\\x99\\x08;#\\x07\\xb970\\xc3\\xeb\\\\\\x0e\\xe4\\xc1\\x1a\\xd4\\x12\\xa6\\x05\\x88v\\xae\\x9e9\\xc28\\x1a\\xb8\\x92b0\\x8c\\xd0\\x96\\x7f\\xcd\\x02K\\x8e\\xfe)\\xc1\\xd1p\\x00\\xbd\\xcf\\xe3\\xf6\\xe8\\x91\\xc9\\x84\\xf5\\x9e\\xacL\\xe0\\x9c/2i8R'"
                    }
                },
                "footer": {
                    "comment": "my_comment"
                },
                "clear": {}
            }
        ]
    ],
    "byte_string": "b'openssh-key-v1\\x00\\x00\\x00\\x00\\naes256-ctr\\x00\\x00\\x00\\x06bcrypt\\x00\\x00\\x00\\x18\\x00\\x00\\x00\\x10\\xfa\\xca\\x90\\x04\\x96\\x83\\xbb\\xe9\\x00\\x05\\'\\x8ev\\x06,t\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x01\\x00\\x00\\x003\\x00\\x00\\x00\\x0bssh-ed25519\\x00\\x00\\x00 \\xd0\\x96\\x7f\\xcd\\x02K\\x8e\\xfe)\\xc1\\xd1p\\x00\\xbd\\xcf\\xe3\\xf6\\xe8\\x91\\xc9\\x84\\xf5\\x9e\\xacL\\xe0\\x9c/2i8R\\x00\\x00\\x00\\x90\\xf9Iu\\x91\\x7f\\x82V\\xe1E2\\x98\\x17\\x82g8jmdy\\xabZz\\x85\\xa5\\xa1\\x05%\\x9a\\xdds\\x18/\\xd2[\\xad\\xd6\\xc6\\xe3\\xb14\\x92\\xa85\\x05BI#7\\x93#\\x07\\x9cu\\xe4\\xcb\\xccJ\\xe2\\x98\\xb4\\xde\\xf8\\x96\\x8f/)2P\\xef\\x02DgO\\x1d\\xe9\\x82\\xc2\\xa0D\\xbe\\x88\\xef\\xb4\\x86\\xbb\"I\\xc0\\x10\\x91\\xebT|\\x9a:\\xaf\\r6MZq\\xba\\xa7|r\\x17=\\xe7\\xaa\\xdeq.\\xa4\\xef\\xdc!\\x12N\\xdf\\x14\\x98\\xec-,~6\\x81.\\xa0\\xec\\xfe[.\\x17\\xf3z\\xbf\\xa1Q\\xbf\\xda\\xb3\\xeeY'",
    "header": {
        "auth_magic": "b'openssh-key-v1\\x00'",
        "cipher": "aes256-ctr",
        "kdf": "bcrypt",
        "kdf_options": "b\"\\x00\\x00\\x00\\x10\\xfa\\xca\\x90\\x04\\x96\\x83\\xbb\\xe9\\x00\\x05'\\x8ev\\x06,t\\x00\\x00\\x00\\x10\"",
        "num_keys": 1
    },
    "cipher_bytes": "b'\\xf9Iu\\x91\\x7f\\x82V\\xe1E2\\x98\\x17\\x82g8jmdy\\xabZz\\x85\\xa5\\xa1\\x05%\\x9a\\xdds\\x18/\\xd2[\\xad\\xd6\\xc6\\xe3\\xb14\\x92\\xa85\\x05BI#7\\x93#\\x07\\x9cu\\xe4\\xcb\\xccJ\\xe2\\x98\\xb4\\xde\\xf8\\x96\\x8f/)2P\\xef\\x02DgO\\x1d\\xe9\\x82\\xc2\\xa0D\\xbe\\x88\\xef\\xb4\\x86\\xbb\"I\\xc0\\x10\\x91\\xebT|\\x9a:\\xaf\\r6MZq\\xba\\xa7|r\\x17=\\xe7\\xaa\\xdeq.\\xa4\\xef\\xdc!\\x12N\\xdf\\x14\\x98\\xec-,~6\\x81.\\xa0\\xec\\xfe[.\\x17\\xf3z\\xbf\\xa1Q\\xbf\\xda\\xb3\\xeeY'",
    "kdf_options": {
        "salt": "b\"\\xfa\\xca\\x90\\x04\\x96\\x83\\xbb\\xe9\\x00\\x05'\\x8ev\\x06,t\"",
        "rounds": 16
    },
    "decipher_bytes": "b'\\xb1\\xe5\\x03+\\xb1\\xe5\\x03+\\x00\\x00\\x00\\x0bssh-ed25519\\x00\\x00\\x00 \\xd0\\x96\\x7f\\xcd\\x02K\\x8e\\xfe)\\xc1\\xd1p\\x00\\xbd\\xcf\\xe3\\xf6\\xe8\\x91\\xc9\\x84\\xf5\\x9e\\xacL\\xe0\\x9c/2i8R\\x00\\x00\\x00@\\x99\\x08;#\\x07\\xb970\\xc3\\xeb\\\\\\x0e\\xe4\\xc1\\x1a\\xd4\\x12\\xa6\\x05\\x88v\\xae\\x9e9\\xc28\\x1a\\xb8\\x92b0\\x8c\\xd0\\x96\\x7f\\xcd\\x02K\\x8e\\xfe)\\xc1\\xd1p\\x00\\xbd\\xcf\\xe3\\xf6\\xe8\\x91\\xc9\\x84\\xf5\\x9e\\xacL\\xe0\\x9c/2i8R\\x00\\x00\\x00\\nmy_comment\\x01\\x02\\x03'",
    "decipher_bytes_header": {
        "check_int_1": 2984575787,
        "check_int_2": 2984575787
    },
    "decipher_padding": "b'\\x01\\x02\\x03'"
}
```
```
$ python -m openssh_key test_id_ed25519.pub
```
```json
[
    {
        "header": {
            "key_type": "ssh-ed25519"
        },
        "params": {
            "data": {
                "public": "b'\\xd0\\x96\\x7f\\xcd\\x02K\\x8e\\xfe)\\xc1\\xd1p\\x00\\xbd\\xcf\\xe3\\xf6\\xe8\\x91\\xc9\\x84\\xf5\\x9e\\xacL\\xe0\\x9c/2i8R'"
            }
        },
        "footer": {},
        "clear": {
            "key_type": "ssh-ed25519",
            "comment": "my_comment"
        }
    }
]
```

### Manipulate a private key file

```
$ python
```
```python
>>> import openssh_key.private_key_list as pkl
>>> sk_list = pkl.PrivateKeyList.from_string(open('test_id_ed25519').read(), passphrase='secret_passphrase')
>>> sk_list
[PublicPrivateKeyPair(public=<openssh_key.key.PublicKey object at 0x7fd0808f6400>, private=<openssh_key.key.PrivateKey object at 0x7fd07f781640>)]
>>> sk_list[0].private.footer
{'comment': 'my_comment'}
>>> sk_list[0].private.footer['comment'] = 'new_comment'
>>> _ = open('modified_test_id_ed25519', 'w').write(sk_list.pack_string(passphrase='new_secret_passphrase'))
>>> _ = open('modified_test_id_ed25519.pub', 'w').write(sk_list[0].public.pack_public_string())
```

### Generate a private key

```python
>>> pk_sk_pair = pkl.PublicPrivateKeyPair.generate('ssh-rsa', 'comment')
>>> generated_sk_list = pkl.PrivateKeyList.from_list([pk_sk_pair], cipher='aes256-ctr', kdf='bcrypt')
>>> _ = open('generated_test_id_rsa', 'w').write(generated_sk_list.pack_string(passphrase='secret_passphrase'))
>>> _ = open('generated_test_id_rsa.pub', 'w').write(generated_pk_key.pack_public_string())
```

### Convert keys to external classes

```python
>>> import cryptography.hazmat.primitives.asymmetric.rsa as rsa
>>> sk_params.convert_to(rsa.RSAPrivateKey)
<cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object at 0x7f74522fadc0>
>>> sk_params.convert_to(rsa.RSAPublicKey)
<cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object at 0x7f74522faac0>
```

## Tests

The package provides a full-coverage test suite and complete type annotations.

```
$ git clone https://github.com/scottcwang/openssh_key_parser.git
$ pip install .
$ pip install -r requirements-dev.txt
$ pytest
```

## Changelog

### 0.0.6

- _Fix_ - Don't dump raw bytes in `pascal_style_byte_stream` exception message (@mike-arnica)
- _Fix_ - Raise `ValueError` instead of `NotImplementedError`

### 0.0.5

- _Fix_ - Fix incorrect key type name for `ecdsa-sha2-*`
- _Fix_ - Fix bad import of `nacl.signing` in `ed25519`
- **Breaking change** - The `create_{cipher,kdf_options,public_key_params,private_key_params}`
  factory methods are renamed to `get_*_class`
- Migrate to `pyproject.toml`

### 0.0.4

- **Breaking change** - The `encrypt` and `decrypt` methods of the `Cipher`
  class now take as arguments an instance of the `KDF` class and a `passphrase`
  (and no longer `cipher_key` and `initialization_vector`)
- **Breaking change** - The `kdf` module has been renamed to `kdf_options`
- Support `aes128-ctr`, `aes192-ctr`, `aes128-cbc`, `aes192-cbc`, `aes256-cbc`,
  `3des-cbc`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`, and
  `chacha20-poly1305@openssh.com` ciphers for private key encryption
- Add a `generate` static method to `PublicPrivateKeyPair`
- _Fix_ - Write an additional newline at the end of a private key file, which
  is required by OpenSSH `ssh-keygen`

### 0.0.3

- 0.0.2 and on requires Python >=3.10 (@FloLie)

### 0.0.2

- Support `ssh-dss`, `ssh-ecdsa-*`, `sk-*@openssh.com` (FIDO/U2F security
  key) and `*-cert-v01@openssh.com` (certificate) key types

### 0.0.1

Initial release, supporting:

- `ssh-rsa` and `ssh-ed25519` key types
- `none` and `aes256-ctr` ciphers for private keys
- `none` and `bcrypt` key derivation functions for ciphers
- OpenSSH key formats

## Security

I'm grateful to Mike Doyle (@mike-arnica), Head of Security Research at Arnica.io, for performing a [security review](https://github.com/scottcwang/openssh_key_parser/pull/5) of version 0.0.6 of `openssh_key_parser`.

To report a vulnerability, please contact me privately at [wangsc@cs.wisc.edu](wangsc@cs.wisc.edu).
