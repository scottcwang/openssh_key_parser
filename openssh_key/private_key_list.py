import collections
import warnings
import getpass
import secrets
import base64

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


OPENSSH_PRIVATE_KEY_HEADER = '-----BEGIN OPENSSH PRIVATE KEY-----'
OPENSSH_PRIVATE_KEY_FOOTER = '-----END OPENSSH PRIVATE KEY-----'

WRAP_COL = 70


class PublicPrivateKeyPair:
    def __init__(self, public, private):
        self.public = public
        self.private = private

    def __eq__(self, other):
        return (
            type(self) is type(other) and
            self.public == other.public and
            self.private == other.private
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

    def __init__(
        self,
        initlist,
        byte_string=None,
        header=None,
        cipher_bytes=None,
        kdf_options=None,
        decipher_bytes=None,
        decipher_bytes_header=None,
        decipher_padding=None
    ):
        super().__init__(initlist)
        self.byte_string = byte_string
        self.header = header
        self.cipher_bytes = cipher_bytes
        self.kdf_options = kdf_options
        self.decipher_bytes = decipher_bytes
        self.decipher_bytes_header = decipher_bytes_header
        self.decipher_padding = decipher_padding

    @classmethod
    def from_bytes(cls, byte_string):
        byte_stream = PascalStyleByteStream(byte_string)

        header = byte_stream.read_from_format_instructions_dict(
            cls.header_format_instructions_dict()
        )

        if header['auth_magic'] != b'openssh-key-v1\x00':
            raise ValueError('Not an openssh-key-v1 key')

        num_keys = header['num_keys']

        if num_keys < 0:
            raise ValueError('Cannot parse negative number of keys')

        initlist = []
        for i in range(num_keys):
            public_key_bytes = byte_stream.read_from_format_instruction(
                PascalStyleFormatInstruction.BYTES
            )
            initlist.append(
                PublicKey.from_bytes(public_key_bytes)
            )

        cipher_bytes = byte_stream.read_from_format_instruction(
            PascalStyleFormatInstruction.BYTES
        )

        kdf_class = create_kdf(header['kdf'])
        kdf_options = PascalStyleByteStream(
            header['kdf_options']
        ).read_from_format_instructions_dict(
            kdf_class.options_format_instructions_dict()
        )

        cipher_class = create_cipher(header['cipher'])

        if kdf_class != NoneKDF:
            passphrase = getpass.getpass('Key passphrase: ')
        else:
            passphrase = ''

        kdf_result = kdf_class.derive_key(kdf_options, passphrase)

        decipher_bytes = cipher_class.decrypt(
            kdf_result.cipher_key,
            kdf_result.initialization_vector,
            cipher_bytes
        )

        decipher_byte_stream = PascalStyleByteStream(decipher_bytes)

        decipher_bytes_header = \
            decipher_byte_stream.read_from_format_instructions_dict(
                cls.decipher_bytes_header_format_instructions_dict()
            )

        if decipher_bytes_header['check_int_1'] \
                != decipher_bytes_header['check_int_2']:
            warnings.warn('Cipher header check numbers do not match')

        for i in range(num_keys):
            initlist[i] = PublicPrivateKeyPair(
                initlist[i],
                PrivateKey.from_byte_stream(decipher_byte_stream)
            )
            if initlist[i].public.header['key_type'] \
                    != initlist[i].private.header['key_type']:
                warnings.warn(
                    f'Inconsistency between private and public '
                    f'key types for key {i}'
                )
            if not all([
                (
                    initlist[i].public.params[k] ==
                    initlist[i].private.params[k]
                ) for k in (
                    initlist[i].public.params.keys() &
                    initlist[i].private.params.keys()
                )
            ]):
                warnings.warn(
                    f'Inconsistency between private and public '
                    f'values for key {i}'
                )

        decipher_padding = decipher_byte_stream.read()

        if (
            len(decipher_byte_stream.getvalue()) %
                cipher_class.block_size() != 0
        ) or not (
            bytes(
                range(1, 1 + cipher_class.block_size())
            ).startswith(decipher_padding)
        ):
            warnings.warn('Incorrect padding at end of ciphertext')

        return cls(
            initlist,
            byte_string,
            header,
            cipher_bytes,
            kdf_options,
            decipher_bytes,
            decipher_bytes_header,
            decipher_padding
        )

    @classmethod
    def from_string(cls, string):
        key_lines = string.splitlines()

        if key_lines[0] != OPENSSH_PRIVATE_KEY_HEADER or \
                key_lines[-1] != OPENSSH_PRIVATE_KEY_FOOTER:
            raise ValueError('Not an openssh private key')
        key_b64 = ''.join(key_lines[1:-1])
        key_bytes = base64.b64decode(key_b64)
        return cls.from_bytes(key_bytes)

    @classmethod
    def from_list(
        cls,
        key_pair_list,
        cipher='none',
        kdf='none',
        kdf_options=None
    ):
        header = {
            'cipher': cipher,
            'kdf': kdf
        }

        initlist = []
        for key_pair in key_pair_list:
            if not isinstance(key_pair, PublicPrivateKeyPair) \
                    or not isinstance(key_pair.public, PublicKey) \
                    or not isinstance(key_pair.private, PrivateKey):
                raise ValueError('Not a key pair')
            initlist.append(key_pair)

        if kdf_options is None:
            kdf_options = {}

        return cls(
            initlist,
            header=header,
            kdf_options=kdf_options
        )

    def pack_bytes(
        self,
        include_indices=None,
        override_public_with_private=True
    ):
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
                    self[i].private.pack_public_bytes()
                    if override_public_with_private
                    else self[i].public.pack_public_bytes()
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
                self[i].private.pack_private_bytes()
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
            kdf_result.cipher_key,
            kdf_result.initialization_vector,
            decipher_byte_stream.getvalue()
        )
        write_byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            cipher_bytes
        )

        return write_byte_stream.getvalue()

    def pack_string(
        self,
        include_indices=None,
        override_public_with_private=True
    ):
        text = OPENSSH_PRIVATE_KEY_HEADER + '\n'
        private_keys_bytes = self.pack_bytes(
            include_indices,
            override_public_with_private
        )
        private_keys_b64 = base64.b64encode(private_keys_bytes).decode()
        private_keys_wrapped = '\n'.join([
            (
                private_keys_b64[
                    i:
                    min(i + WRAP_COL, len(private_keys_b64))
                ]
            )
            for i in range(0, len(private_keys_b64), WRAP_COL)
        ])
        text += private_keys_wrapped
        text += '\n' + OPENSSH_PRIVATE_KEY_FOOTER

        return text
