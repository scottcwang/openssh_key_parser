import abc
import collections
import warnings
import getpass

from openssh_key.pascal_style_byte_stream import (
    PascalStyleFormatInstruction,
    PascalStyleByteStream
)
from openssh_key.key_params import (
    create_public_key_params,
    create_private_key_params
)
from openssh_key.kdf import create_kdf, NoneKDF
from openssh_key.cipher import create_cipher


class PublicKey():
    @staticmethod
    def header_format_instructions_dict():
        return {
            'key_type': PascalStyleFormatInstruction.STRING
        }

    @staticmethod
    def footer_format_instructions_dict():
        return {}

    @staticmethod
    def create_key_params(key_type, byte_stream):
        params_class = create_public_key_params(key_type)
        return params_class(
            byte_stream.read_from_format_instructions_dict(
                create_public_key_params(
                    key_type).public_format_instructions_dict()
            )
        )

    def __init__(self, header, params, footer):
        self.header = header
        self.params = params
        self.footer = footer

    @classmethod
    def from_byte_stream(cls, byte_stream):
        header = byte_stream.read_from_format_instructions_dict(
            cls.header_format_instructions_dict()
        )

        params = cls.create_key_params(
            header['key_type'],
            byte_stream
        )

        footer = byte_stream.read_from_format_instructions_dict(
            cls.footer_format_instructions_dict()
        )

        return cls(header, params, footer)

    @classmethod
    def from_bytes(cls, byte_string):
        byte_stream = PascalStyleByteStream(byte_string)

        key = cls.from_byte_stream(byte_stream)

        key.bytes = byte_string

        remainder = byte_stream.read()
        if len(remainder) > 0:
            warnings.warn(f'Excess bytes in key')
            key.remainder = remainder

        return key

    def pack_public(self):
        key_byte_stream = PascalStyleByteStream()

        key_byte_stream.write_from_format_instructions_dict(
            self.header_format_instructions_dict(),
            self.header
        )

        key_byte_stream.write_from_format_instructions_dict(
            self.params.public_format_instructions_dict(),
            self.params
        )

        key_byte_stream.write_from_format_instructions_dict(
            self.footer_format_instructions_dict(),
            self.footer
        )

        return key_byte_stream.getvalue()


class PrivateKey(PublicKey):
    @staticmethod
    def header_format_instructions_dict():
        return {
            'key_type': PascalStyleFormatInstruction.STRING
        }

    @staticmethod
    def footer_format_instructions_dict():
        return {
            'comment': PascalStyleFormatInstruction.STRING
        }

    @staticmethod
    def create_key_params(key_type, byte_stream):
        params_class = create_private_key_params(key_type)
        return params_class(
            byte_stream.read_from_format_instructions_dict(
                create_private_key_params(
                    key_type).private_format_instructions_dict()
            )
        )

    def pack_private(self):
        key_byte_stream = PascalStyleByteStream()

        key_byte_stream.write_from_format_instructions_dict(
            self.header_format_instructions_dict(),
            self.header
        )

        key_byte_stream.write_from_format_instructions_dict(
            self.params.private_format_instructions_dict(),
            self.params
        )

        key_byte_stream.write_from_format_instructions_dict(
            self.footer_format_instructions_dict(),
            self.footer
        )

        return key_byte_stream.getvalue()


PublicPrivateKeyPair = collections.namedtuple(
    'PublicPrivateKeyPair',
    ['public', 'private']
)


class PrivateKeyList(collections.UserList):
    @staticmethod
    def header_format_instructions_dict():
        return {
            'auth_magic': '15s',
            'cipher': PascalStyleFormatInstruction.STRING,
            'kdf': PascalStyleFormatInstruction.STRING,
            'kdf_options': PascalStyleFormatInstruction.BYTES,
            'num_keys': '>i'
        }

    @staticmethod
    def decipher_bytes_header_format_instructions_dict():
        return {
            'check_int_1': '>I',
            'check_int_2': '>I'
        }

    @classmethod
    def from_bytes(cls, byte_string):
        byte_stream = PascalStyleByteStream(byte_string)

        private_key_list = cls()

        private_key_list.bytes = byte_string

        private_key_list.header = \
            byte_stream.read_from_format_instructions_dict(
                private_key_list.header_format_instructions_dict()
            )

        if private_key_list.header['auth_magic'] != b'openssh-key-v1\x00':
            raise ValueError('Not an openssh-key-v1 key')

        num_keys = private_key_list.header['num_keys']

        if num_keys < 0:
            raise ValueError('Cannot parse negative number of keys')

        for i in range(num_keys):
            public_key_bytes = byte_stream.read_from_format_instruction(
                PascalStyleFormatInstruction.BYTES
            )
            private_key_list.append(
                PublicKey.from_bytes(public_key_bytes)
            )

        private_key_list.cipher_bytes = \
            byte_stream.read_from_format_instruction(
                PascalStyleFormatInstruction.BYTES
            )

        kdf_class = create_kdf(private_key_list.header['kdf'])
        private_key_list.kdf_options = PascalStyleByteStream(
            private_key_list.header['kdf_options']
        ).read_from_format_instructions_dict(
            kdf_class.options_format_instructions_dict()
        )

        cipher_class = create_cipher(private_key_list.header['cipher'])

        if kdf_class != NoneKDF:
            passphrase = getpass.getpass('Key passphrase: ')
        else:
            passphrase = ''

        kdf_result = kdf_class.derive_key(
            private_key_list.kdf_options, passphrase
        )

        private_key_list.decipher_bytes = cipher_class.decrypt(
            kdf_result['cipher_key'],
            kdf_result['initialization_vector'],
            private_key_list.cipher_bytes
        )

        decipher_byte_stream = PascalStyleByteStream(
            private_key_list.decipher_bytes
        )

        private_key_list.decipher_bytes_header = \
            decipher_byte_stream.read_from_format_instructions_dict(
                private_key_list.
                decipher_bytes_header_format_instructions_dict()
            )

        if private_key_list.decipher_bytes_header['check_int_1'] \
                != private_key_list.decipher_bytes_header['check_int_2']:
            warnings.warn('Cipher header check numbers do not match')

        for i in range(num_keys):
            private_key_list[i] = PublicPrivateKeyPair(
                private_key_list[i],
                PrivateKey.from_byte_stream(decipher_byte_stream)
            )
            if private_key_list[i].public.header['key_type'] \
                    != private_key_list[i].private.header['key_type']:
                warnings.warn(
                    f'Inconsistency between private and public '
                    f'key types for key {i}'
                )
            if not all([
                (
                    private_key_list[i].public.params[k]
                    == private_key_list[i].private.params[k]
                ) for k in (
                    private_key_list[i].public.params.keys()
                    & private_key_list[i].private.params.keys()
                )
            ]):
                warnings.warn(
                    f'Inconsistency between private and public '
                    f'values for key {i}'
                )

        private_key_list.decipher_padding = decipher_byte_stream.read()

        if (
            len(decipher_byte_stream.getvalue()) % cipher_class.block_size()
            != 0
        ) or not (
            bytes(
                range(1, 1 + cipher_class.block_size())
            ).startswith(
                private_key_list.decipher_padding
            )
        ):
            warnings.warn('Incorrect padding at end of ciphertext')

        return private_key_list

    @classmethod
    def from_list(
        cls,
        key_pair_list,
        cipher='none',
        kdf='none',
        kdf_options={}
    ):
        private_key_list = cls()

        private_key_list.header = {
            'cipher': cipher,
            'kdf': kdf,
            'kdf_options': kdf_options
        }

        for key_pair in key_pair_list:
            if not isinstance(key_pair, PublicPrivateKeyPair) \
                    or not isinstance(key_pair.public, PublicKey) \
                    or not isinstance(key_pair.private, PrivateKey):
                raise ValueError('Not a key pair')
            private_key_list.append(key_pair)

        return private_key_list

