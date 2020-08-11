import warnings
import base64
import typing
import abc

from openssh_key.pascal_style_byte_stream import (
    PascalStyleFormatInstruction,
    PascalStyleByteStream,
    FormatInstructionsDict,
    ValuesDict
)
from openssh_key.key_params import (
    create_public_key_params,
    PublicKeyParams,
    PublicKeyParamsTypeVar,
    create_private_key_params,
    PrivateKeyParams
)


KeyTypeVar = typing.TypeVar(
    'KeyTypeVar',
    bound='Key[typing.Any]'
)


class Key(typing.Generic[PublicKeyParamsTypeVar]):
    @staticmethod
    def header_format_instructions_dict() -> FormatInstructionsDict:
        return {
            'key_type': PascalStyleFormatInstruction.STRING
        }

    @staticmethod
    def footer_format_instructions_dict() -> FormatInstructionsDict:
        return {}

    @staticmethod
    def create_key_params_dict(
        key_type: str,
        byte_stream: PascalStyleByteStream
    ) -> ValuesDict:
        return byte_stream.read_from_format_instructions_dict(
            create_public_key_params(
                key_type
            ).format_instructions_dict()
        )

    @staticmethod
    @abc.abstractmethod
    def create_key_params(
        key_type: str,
        key_params_dict: ValuesDict
    ) -> PublicKeyParamsTypeVar:
        pass

    def __init__(
        self,
        header: typing.Mapping[str, typing.Any],
        params: typing.Mapping[str, typing.Any],
        footer: typing.Mapping[str, typing.Any],
        clear: typing.Optional[typing.Mapping[str, typing.Any]] = None
    ):
        self.header = dict(header)
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.header,
            self.header_format_instructions_dict()
        )

        self.params = self.create_key_params(header['key_type'], params)

        self.footer = dict(footer)

        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.footer,
            self.footer_format_instructions_dict()
        )

        self.clear = dict(clear) if clear is not None else {}

    @classmethod
    def from_byte_stream(
        cls: typing.Type[KeyTypeVar],
        byte_stream: PascalStyleByteStream,
        clear: typing.Optional[typing.Mapping[str, typing.Any]] = None
    ) -> KeyTypeVar:
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
    def from_bytes(
        cls: typing.Type[KeyTypeVar],
        byte_string: bytes,
        clear: typing.Optional[typing.Mapping[str, typing.Any]] = None
    ) -> KeyTypeVar:
        byte_stream = PascalStyleByteStream(byte_string)

        key = cls.from_byte_stream(byte_stream, clear)

        remainder = byte_stream.read()
        if len(remainder) > 0:
            warnings.warn('Excess bytes in key')
            key.clear['remainder'] = remainder

        return key

    @classmethod
    def from_string(
        cls: typing.Type[KeyTypeVar],
        string: str
    ) -> KeyTypeVar:
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
                'Inconsistency between clear and encoded key types'
            )
        return public_key

    def pack_public_bytes(self) -> bytes:
        key_byte_stream = PascalStyleByteStream()

        key_byte_stream.write_from_format_instructions_dict(
            Key.header_format_instructions_dict(),
            self.header
        )

        self_params_types: typing.Sequence[typing.Type[PublicKeyParams]] = \
             type(self.params).mro()
        first_public_key_params_type = next(
            (
                params_type for params_type in self_params_types
                if not issubclass(params_type, PrivateKeyParams)
            ),
            PublicKeyParams
        )

        key_byte_stream.write_from_format_instructions_dict(
            first_public_key_params_type.format_instructions_dict(),
            self.params
        )

        key_byte_stream.write_from_format_instructions_dict(
            Key.footer_format_instructions_dict(),
            self.footer
        )

        return key_byte_stream.getvalue()

    def pack_public_string(
        self,
        use_footer_comment: bool = True,
        use_clear_comment: bool = True
    ) -> str:
        text = str(self.header['key_type']) + ' '

        public_key_bytes = self.pack_public_bytes()
        public_keys_b64 = base64.b64encode(public_key_bytes).decode()
        text += public_keys_b64

        if use_footer_comment and 'comment' in self.footer:
            text += ' ' + str(self.footer['comment'])
        if use_clear_comment and 'comment' in self.clear:
            text += ' ' + str(self.clear['comment'])

        text += '\n'
        return text

    def __eq__(self, other: typing.Any) -> bool:
        return (
            type(self) is type(other) and
            self.header == other.header and
            self.params == other.params and
            self.footer == other.footer and
            self.clear == other.clear
        )


class PublicKey(Key[PublicKeyParams]):
    @staticmethod
    def create_key_params(
        key_type: str,
        key_params_dict: ValuesDict
    ) -> PublicKeyParams:
        return create_public_key_params(key_type)(key_params_dict)


class PrivateKey(Key[PrivateKeyParams]):
    @staticmethod
    def header_format_instructions_dict() -> FormatInstructionsDict:
        return {
            'key_type': PascalStyleFormatInstruction.STRING
        }

    @staticmethod
    def footer_format_instructions_dict() -> FormatInstructionsDict:
        return {
            'comment': PascalStyleFormatInstruction.STRING
        }

    @staticmethod
    def create_key_params_dict(
        key_type: str,
        byte_stream: PascalStyleByteStream
    ) -> ValuesDict:
        return byte_stream.read_from_format_instructions_dict(
            create_private_key_params(
                key_type
            ).format_instructions_dict()
        )

    @staticmethod
    def create_key_params(
        key_type: str,
        key_params_dict: ValuesDict
    ) -> PrivateKeyParams:
        return create_private_key_params(key_type)(key_params_dict)

    def pack_private_bytes(self) -> bytes:
        key_byte_stream = PascalStyleByteStream()

        key_byte_stream.write_from_format_instructions_dict(
            PrivateKey.header_format_instructions_dict(),
            self.header
        )

        key_byte_stream.write_from_format_instructions_dict(
            self.params.format_instructions_dict(),
            self.params
        )

        key_byte_stream.write_from_format_instructions_dict(
            PrivateKey.footer_format_instructions_dict(),
            self.footer
        )

        return key_byte_stream.getvalue()
