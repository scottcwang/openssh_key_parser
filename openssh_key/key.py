"""Classes representing containers for serializing and deserializing
:any:`PublicKeyParams` objects.
"""

import abc
import base64
import types
import typing
import warnings

from openssh_key import utils
from openssh_key.key_params import (PrivateKeyParams, PublicKeyParams,
                                    PublicKeyParamsTypeVar,
                                    get_private_key_params_class,
                                    get_public_key_params_class)
from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleByteStream,
                                                  PascalStyleFormatInstruction,
                                                  ValuesDict)

KeyTypeVar = typing.TypeVar(
    'KeyTypeVar',
    bound='Key[typing.Any]'
)


class Key(typing.Generic[PublicKeyParamsTypeVar], abc.ABC):
    """A container for a :any:`PublicKeyParams`, an encoded header and footer,
    and cleartext key details.

    Args:
        header
            A :any:`typing.Mapping` with the contents of the encoded header.
        params
            A :any:`typing.Mapping` with the parameter values.
        footer
            A :any:`typing.Mapping` with the contents of the encoded header.
        clear
            A :any:`typing.Mapping` with cleartext key details, if any.
    """
    __HEADER_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {}

    @staticmethod
    @abc.abstractmethod
    def get_header_format_instructions_dict() -> FormatInstructionsDict:
        """The Pascal-style byte stream format instructions for the encoded
        header.
        """
        return types.MappingProxyType(
            Key.__HEADER_FORMAT_INSTRUCTIONS_DICT
        )

    HEADER_FORMAT_INSTRUCTIONS_DICT = utils.readonly_static_property(
        get_header_format_instructions_dict
    )
    """The Pascal-style byte stream format instructions for the encoded
    header.
    """

    __FOOTER_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {}

    @staticmethod
    @abc.abstractmethod
    def get_footer_format_instructions_dict() -> FormatInstructionsDict:
        """The Pascal-style byte stream format instructions for the encoded
        footer.
        """
        return types.MappingProxyType(
            Key.__FOOTER_FORMAT_INSTRUCTIONS_DICT
        )

    FOOTER_FORMAT_INSTRUCTIONS_DICT = utils.readonly_static_property(
        get_footer_format_instructions_dict
    )
    """The Pascal-style byte stream format instructions for the encoded
    footer.
    """

    @staticmethod
    def create_key_params_dict(
        key_type: str,
        byte_stream: PascalStyleByteStream
    ) -> ValuesDict:
        """Reads parameter values from a given bytestream for a given key type.

        Args:
            key_type
                The key type name.
            byte_stream
                The bytestream from which to read.

        Returns:
            A :any:`typing.Mapping` containing the read parameter values.
        """
        return byte_stream.read_from_format_instructions_dict(
            get_public_key_params_class(
                key_type
            ).FORMAT_INSTRUCTIONS_DICT
        )

    @staticmethod
    @abc.abstractmethod
    def create_key_params(
        key_type: str,
        key_params_dict: ValuesDict
    ) -> PublicKeyParamsTypeVar:
        """Converts a :any:`typing.Mapping` of parameter values to a
        :any:`PublicKeyParams` object of a given key type.

        Args:
            key_type
                The key type name.
            key_params_dict
                The parameter values.

        Returns:
            A :any:`PublicKeyParams` containing the parameter values in
            ``key_params_dict``.
        """

    def __init__(
        self,
        header: ValuesDict,
        params: ValuesDict,
        footer: ValuesDict,
        clear: typing.Optional[ValuesDict] = None
    ):
        self.header = dict(header)
        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.header,
            self.HEADER_FORMAT_INSTRUCTIONS_DICT
        )

        self.params = self.create_key_params(header['key_type'], params)

        self.footer = dict(footer)

        PascalStyleByteStream.check_dict_matches_format_instructions_dict(
            self.footer,
            self.FOOTER_FORMAT_INSTRUCTIONS_DICT
        )

        self.clear = dict(clear) if clear is not None else {}

    @classmethod
    def from_byte_stream(
        cls: typing.Type[KeyTypeVar],
        byte_stream: PascalStyleByteStream,
        clear: typing.Optional[ValuesDict] = None
    ) -> KeyTypeVar:
        """Reads parameter values, encoded header, and encoded footer from a
        given bytestream.

        Args:
            byte_stream
                The bytestream from which to read.
            clear
                Cleartext key details to add to the returned object.

        Returns:
            A :any:`Key` object containing the parameter values, encoded
            header, encoded footer, and cleartext key details.
        """
        header = byte_stream.read_from_format_instructions_dict(
            cls.HEADER_FORMAT_INSTRUCTIONS_DICT
        )

        params = cls.create_key_params_dict(
            header['key_type'],
            byte_stream
        )

        footer = byte_stream.read_from_format_instructions_dict(
            cls.FOOTER_FORMAT_INSTRUCTIONS_DICT
        )

        return cls(header, params, footer, clear)

    @classmethod
    def from_bytes(
        cls: typing.Type[KeyTypeVar],
        byte_string: bytes,
        clear: typing.Optional[ValuesDict] = None
    ) -> KeyTypeVar:
        """Parses parameter values, encoded header, and encoded footer from a
        given byte string.

        Args:
            byte_string
                The byte string from which to parse.
            clear
                Cleartext key details to add to the returned object.

        Returns:
            A :any:`Key` object containing the parameter values, encoded
            header, encoded footer, and cleartext key details.

        Raises:
            UserWarning: There are additional bytes in the encoded key than
                would be expected from the key count.
        """
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
        """Parses parameter values, encoded header, encoded footer, and
        cleartext key details from a given string in OpenSSH `public key format
        <https://github.com/openssh/openssh-portable/blob/ed6bef77f5bb5b8f9ca2914478949e29f2f0a780/PROTOCOL#L470>`_.

        Args:
            string
                The string from which to parse.

        Returns:
            A :any:`Key` object containing the parameter values, encoded
            header, encoded footer, and cleartext key details.

        Raises:
            UserWarning: The cleartext key type and the encoded key type do not
                match, or there are additional bytes in the encoded key than
                would be expected from the key count.
        """
        key_split = string.split(' ', maxsplit=2)
        key_type_clear, key_b64 = key_split[0], key_split[1]
        comment_clear = key_split[2] if len(key_split) == 3 else ''
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
        """Packs the public parameter values, encoded header, and encoded
        footer into a byte string.

        Returns:
            A byte string containing the public parameter values, encoded
            header, and encoded footer.
        """
        key_byte_stream = PascalStyleByteStream()

        key_byte_stream.write_from_format_instructions_dict(
            PublicKey.HEADER_FORMAT_INSTRUCTIONS_DICT,
            self.header
        )

        self_params_types: typing.Sequence[typing.Type[typing.Any]] = \
            type(self.params).mro()
        first_public_key_params_type = next(  # pragma: no cover
            (
                params_type for params_type in self_params_types
                if not issubclass(params_type, PrivateKeyParams)
            ),
            PublicKeyParams
        )

        key_byte_stream.write_from_format_instructions_dict(
            first_public_key_params_type.FORMAT_INSTRUCTIONS_DICT,
            self.params
        )

        key_byte_stream.write_from_format_instructions_dict(
            PublicKey.FOOTER_FORMAT_INSTRUCTIONS_DICT,
            self.footer
        )

        return key_byte_stream.getvalue()

    def pack_public_string(
        self,
        use_footer_comment: bool = True,
        use_clear_comment: bool = True
    ) -> str:
        """Packs the parameter values, encoded header, encoded footer, and
        cleartext key details into a string in OpenSSH `public key format
        <https://github.com/openssh/openssh-portable/blob/ed6bef77f5bb5b8f9ca2914478949e29f2f0a780/PROTOCOL#L470>`_.

        Args:
            use_footer_comment
                Append the comment in the footer, if any, as cleartext to the
                encoded string.
            use_clear_comment
                Append the comment in the cleartext key details, if any, to the
                encoded string (if ``use_footer_comment`` is true, appends
                after the comment in the footer).

        Returns:
            A string containing the parameter values, encoded header, encoded
            footer, and cleartext key details.
        """
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
    """A container for a :any:`PublicKeyParams`, an encoded header and footer,
    and cleartext key details.
    """

    __HEADER_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {
        'key_type': PascalStyleFormatInstruction.STRING
    }

    @staticmethod
    def get_header_format_instructions_dict() -> FormatInstructionsDict:
        """The Pascal-style byte stream format instructions for the encoded
        header.
        """
        return types.MappingProxyType(
            PublicKey.__HEADER_FORMAT_INSTRUCTIONS_DICT
        )

    __FOOTER_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {}

    @staticmethod
    def get_footer_format_instructions_dict() -> FormatInstructionsDict:
        """The Pascal-style byte stream format instructions for the encoded
        footer.
        """
        return types.MappingProxyType(
            PublicKey.__FOOTER_FORMAT_INSTRUCTIONS_DICT
        )


    @staticmethod
    def create_key_params(
        key_type: str,
        key_params_dict: ValuesDict
    ) -> PublicKeyParams:
        return get_public_key_params_class(key_type)(key_params_dict)


class PrivateKey(Key[PrivateKeyParams]):
    """A container for a :any:`PrivateKeyParams` and an encoded header and
    footer.
    """

    __HEADER_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {
        'key_type': PascalStyleFormatInstruction.STRING
    }

    @staticmethod
    def get_header_format_instructions_dict() -> FormatInstructionsDict:
        return types.MappingProxyType(
            PrivateKey.__HEADER_FORMAT_INSTRUCTIONS_DICT
        )

    __FOOTER_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {
        'comment': PascalStyleFormatInstruction.STRING
    }
    
    @staticmethod
    def get_footer_format_instructions_dict() -> FormatInstructionsDict:
        return types.MappingProxyType(
            PrivateKey.__FOOTER_FORMAT_INSTRUCTIONS_DICT
        )

    @staticmethod
    def create_key_params_dict(
        key_type: str,
        byte_stream: PascalStyleByteStream
    ) -> ValuesDict:
        return byte_stream.read_from_format_instructions_dict(
            get_private_key_params_class(
                key_type
            ).FORMAT_INSTRUCTIONS_DICT
        )

    @staticmethod
    def create_key_params(
        key_type: str,
        key_params_dict: ValuesDict
    ) -> PrivateKeyParams:
        """Converts a :any:`typing.Mapping` of parameter values to a
        :any:`PrivateKeyParams` object of a given key type.

        Args:
            key_type
                The key type name.
            key_params_dict
                The parameter values.

        Returns:
            A :any:`PrivateKeyParams` containing the parameter values in
            ``key_params_dict``.
        """
        return get_private_key_params_class(key_type)(key_params_dict)

    def pack_private_bytes(self) -> bytes:
        """Packs the private parameter values, encoded header, and encoded
        footer into a byte string.

        Returns:
            A byte string containing the private parameter values, encoded
            header, and encoded footer.
        """
        key_byte_stream = PascalStyleByteStream()

        key_byte_stream.write_from_format_instructions_dict(
            PrivateKey.HEADER_FORMAT_INSTRUCTIONS_DICT,
            self.header
        )

        key_byte_stream.write_from_format_instructions_dict(
            self.params.FORMAT_INSTRUCTIONS_DICT,
            self.params
        )

        key_byte_stream.write_from_format_instructions_dict(
            PrivateKey.FOOTER_FORMAT_INSTRUCTIONS_DICT,
            self.footer
        )

        return key_byte_stream.getvalue()
