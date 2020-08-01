import warnings
import base64

from openssh_key.pascal_style_byte_stream import (
    PascalStyleFormatInstruction,
    PascalStyleByteStream
)
from openssh_key.key_params import (
    create_public_key_params,
    create_private_key_params
)


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
    def create_key_params_dict(key_type, byte_stream):
        return byte_stream.read_from_format_instructions_dict(
            create_public_key_params(
                key_type).public_format_instructions_dict()
        )

    @staticmethod
    def create_key_params(key_type, key_params_dict):
        return create_public_key_params(key_type)(key_params_dict)

    def __init__(self, header, params, footer, clear={}):
        self.header = header
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.header,
            self.header_format_instructions_dict()
        )

        self.params = self.create_key_params(header['key_type'], params)

        self.footer = footer

        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.footer,
            self.footer_format_instructions_dict()
        )

        self.clear = clear

    @classmethod
    def from_byte_stream(cls, byte_stream, clear={}):
        header = byte_stream.read_from_format_instructions_dict(
            cls.header_format_instructions_dict()
        )

        params = cls.create_key_params_dict(
            header['key_type'],
            byte_stream
        )

        footer = byte_stream.read_from_format_instructions_dict(
            cls.footer_format_instructions_dict()
        )

        return cls(header, params, footer, clear)

    @classmethod
    def from_bytes(cls, byte_string, clear={}):
        byte_stream = PascalStyleByteStream(byte_string)

        key = cls.from_byte_stream(byte_stream, clear)

        key.bytes = byte_string

        remainder = byte_stream.read()
        if len(remainder) > 0:
            warnings.warn('Excess bytes in key')
            key.remainder = remainder

        return key

    @classmethod
    def from_string(cls, string):
        key_type_clear, key_b64, comment_clear = string.split(' ', maxsplit=2)
        key_bytes = base64.b64decode(key_b64)
        public_key = cls.from_bytes(
            key_bytes,
            {
                'key_type': key_type_clear,
                'comment': comment_clear
            }
        )
        if public_key.header['key_type'] != key_type_clear:
            warnings.warn(
                f'Inconsistency between clear and encoded key types'
            )
        return public_key

    def pack_public_bytes(self):
        key_byte_stream = PascalStyleByteStream()

        key_byte_stream.write_from_format_instructions_dict(
            PublicKey.header_format_instructions_dict(),
            self.header
        )

        key_byte_stream.write_from_format_instructions_dict(
            self.params.public_format_instructions_dict(),
            self.params
        )

        key_byte_stream.write_from_format_instructions_dict(
            PublicKey.footer_format_instructions_dict(),
            self.footer
        )

        return key_byte_stream.getvalue()

    def pack_public_string(
        self,
        use_footer_comment=True,
        use_clear_comment=True
    ):
        text = self.header['key_type'] + ' '

        public_key_bytes = self.pack_public_bytes()
        public_keys_b64 = base64.b64encode(public_key_bytes).decode()
        text += public_keys_b64

        if use_footer_comment and 'comment' in self.footer:
            text += ' ' + self.footer['comment']
        if use_clear_comment and 'comment' in self.clear:
            text += ' ' + self.clear['comment']

        text += '\n'
        return text

    def __eq__(self, other):
        return (
            type(self) is type(other) and
            self.header == other.header and
            self.params == other.params and
            self.footer == other.footer and
            self.clear == other.clear
        )


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
    def create_key_params_dict(key_type, byte_stream):
        return byte_stream.read_from_format_instructions_dict(
            create_private_key_params(
                key_type).private_format_instructions_dict()
        )

    @staticmethod
    def create_key_params(key_type, key_params_dict):
        return create_private_key_params(key_type)(key_params_dict)

    def pack_private_bytes(self):
        key_byte_stream = PascalStyleByteStream()

        key_byte_stream.write_from_format_instructions_dict(
            PrivateKey.header_format_instructions_dict(),
            self.header
        )

        key_byte_stream.write_from_format_instructions_dict(
            self.params.private_format_instructions_dict(),
            self.params
        )

        key_byte_stream.write_from_format_instructions_dict(
            PrivateKey.footer_format_instructions_dict(),
            self.footer
        )

        return key_byte_stream.getvalue()
