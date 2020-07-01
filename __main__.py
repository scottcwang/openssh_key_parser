#!/usr/bin/env python3

import argparse
import sys
import base64
import io
import getpass
import enum
import struct
import warnings
import pprint
import abc
import secrets

import bcrypt
import cryptography.hazmat.primitives.ciphers as ciphers
import cryptography.hazmat.primitives.ciphers.algorithms as algorithms
import cryptography.hazmat.primitives.ciphers.modes as modes
from cryptography.hazmat.backends import default_backend


OPENSSH_DEFAULT_STRING_LENGTH_SIZE = 4
WRAP_COL = 70


class PascalStyleFormatInstruction(enum.Enum):
    # https://tools.ietf.org/html/rfc4251#section-5
    BYTES = enum.auto()
    STRING = enum.auto()
    MPINT = enum.auto()


class PascalStyleByteStream(io.BytesIO):
    def read_from_format_instruction(
        self,
        format_instruction,
        string_length_size=OPENSSH_DEFAULT_STRING_LENGTH_SIZE
    ):
        if isinstance(format_instruction, str):
            calcsize = struct.calcsize(format_instruction)
            read_bytes = self.read_fixed_bytes(calcsize)
            read_unpack = struct.unpack(format_instruction, read_bytes)
            if len(read_unpack) == 1:
                return read_unpack[0]
            return read_unpack
        elif isinstance(format_instruction, PascalStyleFormatInstruction):
            read_bytes = self.read_pascal_bytes(string_length_size)
            if format_instruction == PascalStyleFormatInstruction.BYTES:
                return read_bytes
            elif format_instruction == PascalStyleFormatInstruction.STRING:
                return read_bytes.decode()
            elif format_instruction == PascalStyleFormatInstruction.MPINT:
                return int.from_bytes(read_bytes, byteorder='big')
        raise NotImplementedError()

    def read_from_format_instructions_dict(self, format_instructions_dict):
        return {
            k: self.read_from_format_instruction(
                **(
                    format_instruction
                    if isinstance(format_instruction, dict)
                    else {'format_instruction': format_instruction}
                )
            )
            for k, format_instruction in format_instructions_dict.items()
        }

    def read_fixed_bytes(self, num_bytes):
        read_bytes = self.read(num_bytes)
        if len(read_bytes) < num_bytes:
            raise EOFError()
        return read_bytes

    def read_pascal_bytes(self, string_length_size):
        length = int.from_bytes(
            self.read_fixed_bytes(string_length_size),
            byteorder='big'
        )
        return self.read_fixed_bytes(length)

    def write_from_format_instruction(
        self,
        format_instruction,
        value,
        string_length_size=OPENSSH_DEFAULT_STRING_LENGTH_SIZE
    ):
        write_bytes = None
        if isinstance(format_instruction, str):
            write_bytes = struct.pack(format_instruction, value)
        elif isinstance(format_instruction, PascalStyleFormatInstruction):
            if format_instruction == PascalStyleFormatInstruction.BYTES:
                assert isinstance(value, bytes)
                write_bytes = value
            elif format_instruction == PascalStyleFormatInstruction.STRING:
                assert isinstance(value, str)
                write_bytes = value.encode()
            elif format_instruction == PascalStyleFormatInstruction.MPINT:
                assert isinstance(value, int)
                write_bytes = value.to_bytes(
                    length=value.bit_length(),
                    byteorder='big',
                    signed=True
                )
                if value > 0 and write_bytes[0] // 128 == 1:
                    write_bytes = b'\x00' + write_bytes
            write_bytes_len_bytes = len(write_bytes).to_bytes(
                length=OPENSSH_DEFAULT_STRING_LENGTH_SIZE,
                byteorder='big',
                signed=False
            )
            write_bytes = write_bytes_len_bytes + write_bytes
        if write_bytes is None:
            raise NotImplementedError()
        self.write(write_bytes)
        return

    def write_from_format_instructions_dict(
        self,
        format_instructions_dict,
        values_dict
    ):
        for k, v in format_instructions_dict.items():
            self.write_from_format_instruction(
                v,
                values_dict[k]
            )


class KDF(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def derive_key(options, passphrase):
        pass


class NoneKDF(KDF):
    @staticmethod
    def derive_key(options, passphrase):
        return {
            'cipher_key': b'',
            'initialization_vector': b''
        }


class BcryptKDF(KDF):
    @staticmethod
    def derive_key(options, passphrase):
        bcrypt_result = bcrypt.kdf(
            password=passphrase.encode(),
            salt=options['salt'],
            desired_key_bytes=32+16,  # https://blog.rebased.pl/2020/03/24/basic-key-security.html
            rounds=options['rounds']
        )
        return {
            'cipher_key': bcrypt_result[:32],
            'initialization_vector': bcrypt_result[-16:]
        }


_kdf = {
    'none': {
        'kdf': NoneKDF,
        'options_format': {'': '0s'}
    },
    'bcrypt': {
        'kdf': BcryptKDF,
        'options_format': {
            'salt': PascalStyleFormatInstruction.BYTES,
            'rounds': '>I'
        }
    }
}


class Cipher(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def encrypt(cipher_key, initialization_vector, cipher_bytes):
        pass

    @staticmethod
    @abc.abstractmethod
    def decrypt(cipher_key, initialization_vector, cipher_bytes):
        pass


class NoneCipher(Cipher):
    @staticmethod
    def encrypt(cipher_key, initialization_vector, cipher_bytes):
        return cipher_bytes

    @staticmethod
    def decrypt(cipher_key, initialization_vector, cipher_bytes):
        return cipher_bytes


class AES_GCM(Cipher):
    @staticmethod
    def encrypt(cipher_key, initialization_vector, cipher_bytes):
        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(cipher_bytes) + encryptor.finalize()

    @staticmethod
    def decrypt(cipher_key, initialization_vector, cipher_bytes):
        cipher = ciphers.Cipher(
            algorithms.AES(cipher_key),
            modes.CTR(initialization_vector),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(cipher_bytes) + decryptor.finalize()


_cipher = {
    'none': NoneCipher,
    'aes256-ctr': AES_GCM
}


_clear_bytes_header = {
    'auth_magic': '15s',
    'cipher': PascalStyleFormatInstruction.STRING,
    'kdf': PascalStyleFormatInstruction.STRING,
    'kdf_options': PascalStyleFormatInstruction.BYTES,
    'num_keys': '>i'
}

_key_header = {
    'key_type': PascalStyleFormatInstruction.STRING
}

_public_key = {
    'ssh-rsa': {
        'e': PascalStyleFormatInstruction.MPINT,
        'n': PascalStyleFormatInstruction.MPINT,
    },
    'ssh-ed25519': {
        'public': PascalStyleFormatInstruction.BYTES
    }
}

_cipher_bytes_header = {
    'check_int_1': '>I',
    'check_int_2': '>I'
}

_private_key = {
    'ssh-rsa': {
        'n': PascalStyleFormatInstruction.MPINT,
        'e': PascalStyleFormatInstruction.MPINT,
        'd': PascalStyleFormatInstruction.MPINT,
        'iqmp': PascalStyleFormatInstruction.MPINT,
        'p': PascalStyleFormatInstruction.MPINT,
        'q': PascalStyleFormatInstruction.MPINT,
    },
    'ssh-ed25519': {
        'public': PascalStyleFormatInstruction.BYTES,
        'private_public': PascalStyleFormatInstruction.BYTES
    }
}

_private_key_footer = {
    'comment': PascalStyleFormatInstruction.STRING
}


def parse_file(filename):
    with open(filename) as fd:
        key_lines = fd.read().splitlines()
        if key_lines[0] == "-----BEGIN OPENSSH PRIVATE KEY-----" \
                and key_lines[-1] == "-----END OPENSSH PRIVATE KEY-----":
            key_b64 = ''.join(key_lines[1:-1])
            key_bytes = base64.b64decode(key_b64)
            return parse_private_bytes(key_bytes)

        else:
            key = {'keys': []}
            for i, key_line in enumerate(key_lines):
                public_key = {}
                public_key['key_type_clear'], key_b64, public_key['comment'] = key_line.split(
                    ' ', maxsplit=2)
                key_bytes = base64.b64decode(key_b64)
                public_key.update(parse_public_bytes(key_bytes))
                if public_key['key_type'] != public_key['key_type_clear']:
                    warnings.warn(
                        f'Inconsistency between clear and encoded key types for key {i}')
                key['keys'].append(public_key)
            return key


def parse_public_bytes(public_bytes):
    public_key_byte_stream = PascalStyleByteStream(public_bytes)
    public_key = public_key_byte_stream.read_from_format_instructions_dict(
        _key_header)
    if public_key['key_type'] not in _public_key:
        warnings.warn('Unsupported public key type')
        public_key['public_bytes'] = public_key_byte_stream.read()
        return public_key
    public_key['values'] = public_key_byte_stream.read_from_format_instructions_dict(
        _public_key[public_key['key_type']])
    remainder = public_key_byte_stream.read()
    if len(remainder) > 0:
        warnings.warn(f'Excess bytes in public key')
        public_key['remainder'] = remainder
    return public_key


def parse_private_bytes(private_bytes):
    # https://github.com/openssh/openssh-portable/blob/5c68ea8da790d711e6dd5f4c30d089c54032c59a/PROTOCOL.key
    # https://coolaj86.com/articles/the-openssh-private-key-format
    # https://github.com/valohai/openssh-key
    # https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-4.2

    byte_stream = PascalStyleByteStream(private_bytes)

    key = byte_stream.read_from_format_instructions_dict(
        _clear_bytes_header)

    if key['auth_magic'] != b'openssh-key-v1\x00':
        raise ValueError('Not an openssh-key-v1 key')

    num_keys = key['num_keys']

    key['keys'] = []
    for i in range(num_keys):
        public_key_bytes = byte_stream.read_from_format_instruction(
            PascalStyleFormatInstruction.BYTES)
        key['keys'].append({'public': parse_public_bytes(public_key_bytes)})

    private_bytes = byte_stream.read_from_format_instruction(
        PascalStyleFormatInstruction.BYTES)

    if key['kdf'] != 'none':
        passphrase = getpass.getpass('Key passphrase: ')
    else:
        passphrase = ''

    if key['kdf'] not in _kdf:
        warnings.warn('Unsupported KDF type')
        key['private_bytes'] = private_bytes
        return key

    key['kdf_options'] = PascalStyleByteStream(
        key['kdf_options']
    ).read_from_format_instructions_dict(
        _kdf[key['kdf']]['options_format']
    )
    kdf_result = _kdf[key['kdf']]['kdf'].derive_key(
        key['kdf_options'], passphrase)

    if key['cipher'] not in _cipher:
        warnings.warn('Unsupported cipher type')
        key['private_bytes'] = private_bytes
        return key

    cipher_bytes_decrypted = _cipher[key['cipher']].decrypt(
        kdf_result['cipher_key'],
        kdf_result['initialization_vector'],
        private_bytes
    )

    cipher_byte_stream = PascalStyleByteStream(cipher_bytes_decrypted)

    key['cipher_header'] = cipher_byte_stream.read_from_format_instructions_dict(
        _cipher_bytes_header)
    if key['cipher_header']['check_int_1'] != key['cipher_header']['check_int_2']:
        warnings.warn('Cipher header check numbers do not match')
        key['private_bytes'] = private_bytes
    else:
        for i in range(num_keys):
            private_key = cipher_byte_stream.read_from_format_instructions_dict(
                _key_header)
            if private_key['key_type'] != key['keys'][i]['public']['key_type']:
                warnings.warn(
                    f'Inconsistency between private and public key types for key {i}')
            if private_key['key_type'] not in _private_key:
                warnings.warn('Unsupported private key type')
                private_key['value_bytes'] = cipher_byte_stream.read()
                key['keys'][i]['private'] = private_key
                continue
            private_key['values'] = cipher_byte_stream.read_from_format_instructions_dict(
                _private_key[private_key['key_type']])
            if not all([
                private_key['values'][k] == v
                for k, v in key['keys'][i]['public']['values'].items()
            ]):
                warnings.warn(
                    f'Inconsistency between private and public values for key {i}')
            private_key['footer'] = cipher_byte_stream.read_from_format_instructions_dict(
                _private_key_footer)
            key['keys'][i]['private'] = private_key

        key['padding'] = cipher_byte_stream.read()
        if not b'\x01\x02\x03\x04\x05\x06\x07\x08'.startswith(key['padding']):
            warnings.warn('Incorrect padding at end of ciphertext')

    return key


def pack_public_text_from_public_dict(filename, key_dict):
    text_stream = io.StringIO('')
    for key in key_dict['keys']:
        text_stream.write(key['public']['key_type'] + ' ')
        public_key_bytes = pack_public_key(key['public'])
        public_keys_b64 = base64.b64encode(public_key_bytes).decode()
        text_stream.write(public_keys_b64 + ' ')
        text_stream.write(key['comment'])
        text_stream.write('\n')
    with open(filename, 'w') as fd:
        fd.write(text_stream.getvalue())


def pack_public_text_from_private_dict(filename, key_dict):
    text_stream = io.StringIO('')
    for key in key_dict['keys']:
        text_stream.write(key['private']['key_type'] + ' ')
        public_key_bytes = pack_public_key(key['private'])
        public_keys_b64 = base64.b64encode(public_key_bytes).decode()
        text_stream.write(public_keys_b64 + ' ')
        text_stream.write(key['private']['footer']['comment'])
        text_stream.write('\n')
    with open(filename, 'w') as fd:
        fd.write(text_stream.getvalue())


def pack_private_text(filename, key_dict, cipher='none', kdf='none', kdf_options={'': b''}):
    text_stream = io.StringIO('')
    text_stream.write('-----BEGIN OPENSSH PRIVATE KEY-----\n')
    private_keys_bytes = pack_private_keys(
        key_dict['keys'], cipher, kdf, kdf_options)
    private_keys_b64 = base64.b64encode(private_keys_bytes).decode()
    private_keys_wrapped = ''.join([
        (private_keys_b64[i: min(i + WRAP_COL, len(private_keys_b64))] + '\n')
        for i in range(0, len(private_keys_b64), WRAP_COL)
    ])
    text_stream.write(private_keys_wrapped)
    text_stream.write('-----END OPENSSH PRIVATE KEY-----\n')
    with open(filename, 'w') as fd:
        fd.write(text_stream.getvalue())


def pack_public_key(public_key):
    byte_stream = PascalStyleByteStream(b'')

    byte_stream.write_from_format_instructions_dict(
        _key_header, public_key
    )
    byte_stream.write_from_format_instructions_dict(
        _public_key[public_key['key_type']], public_key['values']
    )

    return byte_stream.getvalue()


def pack_private_keys(private_keys, cipher='none', kdf='none', kdf_options={'': b''}):
    if cipher not in _cipher:
        raise NotImplementedError('Unsupported cipher')
    if kdf not in _kdf:
        raise NotImplementedError('Unsupported KDF')

    kdf_options_byte_stream = PascalStyleByteStream(b'')
    kdf_options_byte_stream.write_from_format_instructions_dict(
        _kdf[kdf]['options_format'], kdf_options
    )

    byte_stream = PascalStyleByteStream(b'')
    clear_bytes_header = {
        'auth_magic': b'openssh-key-v1\x00',
        'cipher': cipher,
        'kdf': kdf,
        'kdf_options': kdf_options_byte_stream.getvalue(),
        'num_keys': len(private_keys)
    }
    byte_stream.write_from_format_instructions_dict(
        _clear_bytes_header, clear_bytes_header
    )

    cipher_byte_stream = PascalStyleByteStream(b'')
    check_int = secrets.randbits(32)
    cipher_bytes_header = {
        'check_int_1': check_int,
        'check_int_2': check_int
    }
    cipher_byte_stream.write_from_format_instructions_dict(
        _cipher_bytes_header, cipher_bytes_header)

    for key in private_keys:  # openssh only supports one key at a time: https://github.com/openssh/openssh-portable/blob/e073106f370cdd2679e41f6f55a37b491f0e82fe/sshkey.c#L4067
        byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            pack_public_key(key['private'])
        )

        cipher_byte_stream.write_from_format_instructions_dict(
            _key_header,
            key['private']
        )
        cipher_byte_stream.write_from_format_instructions_dict(
            _private_key[key['private']['key_type']],
            key['private']['values']
        )
        cipher_byte_stream.write_from_format_instructions_dict(
            _private_key_footer,
            key['private']['footer']
        )

    if kdf != 'none':
        passphrase = getpass.getpass('Key passphrase: ')
    else:
        passphrase = ''
    kdf_result = _kdf[kdf]['kdf'].derive_key(kdf_options, passphrase)

    cipher_bytes = cipher_byte_stream.getvalue()
    cipher_bytes = cipher_bytes + \
        (b'\x01\x02\x03\x04\x05\x06\x07\x08')[
            :(-len(cipher_bytes)) % 8]  # TODO Pad to cipher-appropriate block size: https://github.com/openssh/openssh-portable/blob/90e51d672711c19a36573be1785caf35019ae7a8/cipher-aesctr.h#L23
    cipher_bytes_encrypted = _cipher[cipher].encrypt(
        kdf_result['cipher_key'],
        kdf_result['initialization_vector'],
        cipher_bytes
    )
    byte_stream.write_from_format_instruction(
        PascalStyleFormatInstruction.BYTES,
        cipher_bytes_encrypted
    )

    return byte_stream.getvalue()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    args = parser.parse_args()

    pprint.pprint(parse_file(args.filename))
