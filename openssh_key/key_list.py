import abc
import collections
import warnings
import getpass
import secrets

from openssh_key.key import (
    PublicKey,
    PrivateKey
)
from openssh_key.pascal_style_byte_stream import (
    PascalStyleFormatInstruction,
    PascalStyleByteStream
)
from openssh_key.kdf import create_kdf, NoneKDF
from openssh_key.cipher import create_cipher


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
                    private_key_list[i].public.params[k] ==
                    private_key_list[i].private.params[k]
                ) for k in (
                    private_key_list[i].public.params.keys() &
                    private_key_list[i].private.params.keys()
                )
            ]):
                warnings.warn(
                    f'Inconsistency between private and public '
                    f'values for key {i}'
                )

        private_key_list.decipher_padding = decipher_byte_stream.read()

        if (
            len(decipher_byte_stream.getvalue()) %
                cipher_class.block_size() != 0
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
            'kdf': kdf
        }

        private_key_list.kdf_options = kdf_options

        for key_pair in key_pair_list:
            if not isinstance(key_pair, PublicPrivateKeyPair) \
                    or not isinstance(key_pair.public, PublicKey) \
                    or not isinstance(key_pair.private, PrivateKey):
                raise ValueError('Not a key pair')
            private_key_list.append(key_pair)

        return private_key_list

    def pack(self, include_indices=None, override_public_with_private=True):
        cipher = self.header['cipher']

        kdf = self.header['kdf']

        kdf_options = self.kdf_options

        if include_indices is None:
            include_indices = list(range(len(self)))

        write_byte_stream = PascalStyleByteStream()

        kdf_options_write_byte_stream = PascalStyleByteStream()

        kdf_options_write_byte_stream.write_from_format_instructions_dict(
            create_kdf(kdf).options_format_instructions_dict(),
            kdf_options
        )
        kdf_options_bytes = kdf_options_write_byte_stream.getvalue()

        header = {
            'auth_magic': b'openssh-key-v1\x00',
            'cipher': cipher,
            'kdf': kdf,
            'kdf_options': kdf_options_bytes,
            'num_keys': len(include_indices)
        }
        write_byte_stream.write_from_format_instructions_dict(
            PrivateKeyList.header_format_instructions_dict(),
            header
        )

        for i in include_indices:
            write_byte_stream.write_from_format_instruction(
                PascalStyleFormatInstruction.BYTES,
                (
                    self[i].private.pack_public()
                    if override_public_with_private
                    else self[i].public.pack_public()
                )
            )

        decipher_byte_stream = PascalStyleByteStream()

        check_int = secrets.randbits(32)
        decipher_bytes_header = {
            'check_int_1': check_int,
            'check_int_2': check_int
        }
        decipher_byte_stream.write_from_format_instructions_dict(
            PrivateKeyList.decipher_bytes_header_format_instructions_dict(),
            decipher_bytes_header
        )

        for i in include_indices:
            decipher_byte_stream.write(
                self[i].private.pack_private()
            )

        padding_length = (-len(decipher_byte_stream.getvalue())) \
            % create_cipher(cipher).block_size()
        padding_bytes = bytes(range(1, 1 + padding_length))
        decipher_byte_stream.write(padding_bytes)

        if kdf != 'none':
            passphrase = getpass.getpass('Key passphrase: ')
        else:
            passphrase = ''

        kdf_result = create_kdf(kdf).derive_key(kdf_options, passphrase)
        cipher_bytes = create_cipher(cipher).encrypt(
            kdf_result['cipher_key'],
            kdf_result['initialization_vector'],
            decipher_byte_stream.getvalue()
        )
        write_byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            cipher_bytes
        )

        return write_byte_stream.getvalue()
