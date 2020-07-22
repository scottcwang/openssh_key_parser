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


class Key():
    pass


class PublicKey(Key):
    @staticmethod
    def header_format_instructions_dict():
        return {
            'key_type': PascalStyleFormatInstruction.STRING
        }

    @staticmethod
    def footer_format_instructions_dict():
        return {}

    def __init__(self, key_byte_stream):
        self.header = key_byte_stream.read_from_format_instructions_dict(
            self.header_format_instructions_dict()
        )

        params_class = create_public_key_params(self.header['key_type'])
        self.params = params_class(
            key_byte_stream.read_from_format_instructions_dict(
                create_public_key_params(
                    self.header['key_type']
                ).public_format_instructions_dict()
            )
        )

        self.footer = key_byte_stream.read_from_format_instructions_dict(
            self.footer_format_instructions_dict()
        )

    @classmethod
    def from_byte_stream(cls, byte_stream: PascalStyleByteStream):
        public_key = cls(byte_stream)

        public_key.bytes = byte_stream.getvalue()

        remainder = byte_stream.read()
        if len(remainder) > 0:
            warnings.warn(f'Excess bytes in public key')
            public_key.remainder = remainder

        return public_key


class PrivateKey(Key):
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

    def __init__(self, key_byte_stream):
        self.header = key_byte_stream.read_from_format_instructions_dict(
            self.header_format_instructions_dict()
        )

        params_class = create_private_key_params(self.header['key_type'])
        self.params = params_class(
            key_byte_stream.read_from_format_instructions_dict(
                create_private_key_params(
                    self.header['key_type']
                ).private_format_instructions_dict()
            )
        )

        self.footer = key_byte_stream.read_from_format_instructions_dict(
            self.footer_format_instructions_dict()
        )


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
    def from_byte_stream(cls, byte_stream: PascalStyleByteStream):
        private_key_list = cls()

        private_key_list.bytes = byte_stream.getvalue()

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
            public_key_byte_stream = PascalStyleByteStream(
                byte_stream.read_from_format_instruction(
                    PascalStyleFormatInstruction.BYTES
                )
            )
            private_key_list.append(
                PublicKey.from_byte_stream(public_key_byte_stream)
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
                PrivateKey(decipher_byte_stream)
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
