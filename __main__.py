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

import bcrypt
import cryptography.hazmat.primitives.ciphers as ciphers
import cryptography.hazmat.primitives.ciphers.algorithms as algorithms
import cryptography.hazmat.primitives.ciphers.modes as modes
from cryptography.hazmat.backends import default_backend


OPENSSH_DEFAULT_STRING_LENGTH_SIZE = 4


class PascalStyleFormatInstruction(enum.Enum):
    # https://tools.ietf.org/html/rfc4251#section-5
    BYTES = enum.auto()
    STRING = enum.auto()
    MPINT = enum.auto()
    FIXED = enum.auto()


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
    def decrypt(cipher_key, initialization_vector, cipher_bytes):
        pass


class NoneCipher(Cipher):
    @staticmethod
    def decrypt(cipher_key, initialization_vector, cipher_bytes):
        return cipher_bytes


class AES_GCM(Cipher):
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
    'kdf_name': PascalStyleFormatInstruction.STRING,
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
    'checkint1': '>i',
    'checkint2': '>i'
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

    if key['kdf_name'] != 'none':
        passphrase = getpass.getpass('Key passphrase: ')
    else:
        passphrase = ''

    key['kdf_options'] = PascalStyleByteStream(
        key['kdf_options']
    ).read_from_format_instructions_dict(
        _kdf[key['kdf_name']]['options_format']
    )
    kdf_result = _kdf[key['kdf_name']]['kdf'].derive_key(
        key['kdf_options'], passphrase)

    cipher_bytes_decrypted = _cipher[key['cipher']].decrypt(
        kdf_result['cipher_key'],
        kdf_result['initialization_vector'],
        private_bytes
    )

    cipher_byte_stream = PascalStyleByteStream(cipher_bytes_decrypted)

    key['cipher_header'] = cipher_byte_stream.read_from_format_instructions_dict(
        _cipher_bytes_header)
    if key['cipher_header']['checkint1'] != key['cipher_header']['checkint2']:
        warnings.warn('Cipher header check numbers do not match')
        key['private_bytes'] = private_bytes
    else:
        for i in range(num_keys):
            private_key = cipher_byte_stream.read_from_format_instructions_dict(
                _key_header)
            if private_key['key_type'] != key['keys'][i]['public']['key_type']:
                warnings.warn(
                    f'Inconsistency between private and public key types for key {i}')
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    args = parser.parse_args()

    pprint.pprint(parse_file(args.filename))
