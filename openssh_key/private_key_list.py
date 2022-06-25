"""A class representing a container for serializing and deserializing a list of
private keys, as well as the metadata needed to encrypt and decrypt private
bytes.
"""

import base64
import collections
import getpass
import secrets
import types
import typing
import warnings

from openssh_key import utils
from openssh_key.cipher import ConfidentialityIntegrityCipher, get_cipher_class
from openssh_key.kdf_options import (KDFOptions, NoneKDFOptions,
                                     get_kdf_options_class)
from openssh_key.key import PrivateKey, PublicKey
from openssh_key.key_params import get_private_key_params_class
from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleByteStream,
                                                  PascalStyleFormatInstruction,
                                                  ValuesDict)


class PublicPrivateKeyPair(typing.NamedTuple):
    """
    A public key and its corresponding private key.
    """

    public: PublicKey
    """
    The public key.
    """

    private: PrivateKey
    """
    The corresponding private key.
    """

    def __eq__(self, other: typing.Any) -> bool:
        return (
            type(self) is type(other) and
            self.public == other.public and
            self.private == other.private
        )

    @staticmethod
    def generate(
        key_type: str,
        comment: str = '',
        **kwargs: typing.Any
    ) -> 'PublicPrivateKeyPair':
        """Generates a private key of the given type, with an optional comment
        for the private key.

        Args:
            key_type
                The OpenSSH name of the key type.
            comment
                The comment for the private key. Default is empty string.

        Returns:
            A generated public key and its corresponding private key.
        """
        private_key_class = get_private_key_params_class(key_type)
        private_key_params = private_key_class.generate_private_params(
            **kwargs)
        private_key = PrivateKey(
            header={
                'key_type': key_type
            },
            params=private_key_params,
            footer={
                'comment': comment
            }
        )
        public_key = PublicKey(
            header={
                'key_type': key_type
            },
            params=private_key_params,
            footer={}
        )
        return PublicPrivateKeyPair(public_key, private_key)


PrivateKeyListTypeVar = typing.TypeVar(
    'PrivateKeyListTypeVar',
    bound='PrivateKeyList'
)


# https://github.com/python/mypy/issues/5264
if typing.TYPE_CHECKING:  # pragma: no cover
    BaseList = collections.UserList[  # pylint: disable=unsubscriptable-object
        PublicPrivateKeyPair
    ]
else:
    BaseList = collections.UserList


class PrivateKeyList(BaseList):
    """A container for multiple pairs of :any:`PublicKey` and
    :any:`PrivateKey`.

    The format of an OpenSSH private key list file is specified in the
    `openssh-key-v1 vendor extension <https://github.com/openssh/openssh-portable/blob/bcd00abd8451f36142ae2ee10cc657202149201e/PROTOCOL.key>`_,
    base64-encoded with a
    `PEM-style header and footer <https://github.com/openssh/openssh-portable/blob/e073106f370cdd2679e41f6f55a37b491f0e82fe/sshkey.c#L69>`_
    (wrapped at `70 characters per line <https://github.com/openssh/openssh-portable/blob/bb52e70fa5330070ec9a23069c311d9e277bbd6f/sshbuf-misc.c#L114>`_).

    At present, `OpenSSH only supports one key in a private key list file
    <https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L4067>`_.

    Args:
        initlist
            A list of pairs of :any:`PublicKey` and :any:`PrivateKey`.
        byte_string
            The original byte string from which ``initlist`` was parsed.
        header
            The values in the encoded header of the key list.
        cipher_bytes
            The original encrypted private byte string.
        kdf_options
            The values in the key derivation function parameters.
        decipher_bytes
            The original decrypted private byte string.
        decipher_bytes_header
            The values in the header of the decrypted private byte string.
        decipher_padding
            The values that pad the decrypted private byte string.
    """

    __HEADER_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {
        'auth_magic': '15s',
        'cipher': PascalStyleFormatInstruction.STRING,
        'kdf': PascalStyleFormatInstruction.STRING,
        'kdf_options': PascalStyleFormatInstruction.BYTES,
        'num_keys': '>i'
    }

    @staticmethod
    def get_header_format_instructions_dict() -> FormatInstructionsDict:
        """The Pascal-style byte stream format instructions for the encoded
        header of the key list.
        """
        return types.MappingProxyType(
            PrivateKeyList.__HEADER_FORMAT_INSTRUCTIONS_DICT
        )

    HEADER_FORMAT_INSTRUCTIONS_DICT = utils.readonly_static_property(
        get_header_format_instructions_dict
    )
    """The Pascal-style byte stream format instructions for the encoded
    header of the key list.
    """

    __DECIPHER_BYTES_HEADER_FORMAT_INSTRUCTIONS_DICT: typing.ClassVar[
        FormatInstructionsDict
    ] = {
        'check_int_1': '>I',
        'check_int_2': '>I'
    }

    @staticmethod
    def get_decipher_bytes_header_format_instructions_dict() -> FormatInstructionsDict:
        """The Pascal-style byte stream format instructions for the header of
        the decrypted private byte string.
        """
        return types.MappingProxyType(
            PrivateKeyList.__DECIPHER_BYTES_HEADER_FORMAT_INSTRUCTIONS_DICT
        )

    DECIPHER_BYTES_HEADER_FORMAT_INSTRUCTIONS_DICT = utils.readonly_static_property(
        get_decipher_bytes_header_format_instructions_dict
    )
    """The Pascal-style byte stream format instructions for the header of
    the decrypted private byte string.
    """

    def __init__(
        self,
        initlist: typing.List[PublicPrivateKeyPair],
        byte_string: typing.Optional[bytes] = None,
        header: typing.Optional[ValuesDict] = None,
        cipher_bytes: typing.Optional[bytes] = None,
        kdf_options: typing.Optional[KDFOptions] = None,
        decipher_bytes: typing.Optional[bytes] = None,
        decipher_bytes_header: typing.Optional[ValuesDict] = None,
        decipher_padding: typing.Optional[bytes] = None
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
    def from_bytes(
        cls: typing.Type[PrivateKeyListTypeVar],
        byte_string: bytes,
        passphrase: typing.Optional[str] = None
    ) -> PrivateKeyListTypeVar:
        """Parses a private key list from a given byte string.

        Args:
            byte_string
                The byte string from which to parse.
            passphrase
                The passphrase with which to decrypt the private byte string.
                If not provided, will be prompted for at standard input.

        Returns:
            A :any:`PrivateKeyList` object containing the private key list.

        Raises:
            ValueError: The provided byte string is not an ``openssh-key-v1``
                key list, when the declared key count is negative, or when an
                EOF is found while parsing the key.

            UserWarning: The check numbers in the decrypted private byte string
                do not match (likely due to an incorrect passphrase), the key
                type or parameter values of a private key do not match that of
                the corresponding public key in the list, or the padding bytes
                at the end of the decrypted private byte string are not as
                expected.
        """
        try:
            byte_stream = PascalStyleByteStream(byte_string)

            header = byte_stream.read_from_format_instructions_dict(
                cls.HEADER_FORMAT_INSTRUCTIONS_DICT
            )

            if header['auth_magic'] != b'openssh-key-v1\x00':
                raise ValueError('Not an openssh-key-v1 key')

            num_keys = header['num_keys']

            if num_keys < 0:
                raise ValueError('Cannot parse negative number of keys')

            public_key_list = []
            for i in range(num_keys):
                public_key_bytes = byte_stream.read_from_format_instruction(
                    PascalStyleFormatInstruction.BYTES
                )
                public_key_list.append(
                    PublicKey.from_bytes(public_key_bytes)
                )

            cipher_bytes = byte_stream.read_from_format_instruction(
                PascalStyleFormatInstruction.BYTES
            )

            kdf_class = get_kdf_options_class(header['kdf'])
            kdf_options = kdf_class(
                PascalStyleByteStream(
                    header['kdf_options']
                ).read_from_format_instructions_dict(
                    kdf_class.FORMAT_INSTRUCTIONS_DICT
                )
            )

            cipher_class = get_cipher_class(header['cipher'])

            if kdf_class == NoneKDFOptions:
                passphrase = ''
            elif passphrase is None:
                passphrase = getpass.getpass('Key passphrase: ')

            if issubclass(cipher_class, ConfidentialityIntegrityCipher):
                cipher_bytes += byte_stream.read_fixed_bytes(
                    cipher_class.TAG_LENGTH
                )

            decipher_bytes = cipher_class.decrypt(
                kdf_class(kdf_options),
                passphrase,
                cipher_bytes
            )

            decipher_byte_stream = PascalStyleByteStream(decipher_bytes)

            decipher_bytes_header = \
                decipher_byte_stream.read_from_format_instructions_dict(
                    cls.DECIPHER_BYTES_HEADER_FORMAT_INSTRUCTIONS_DICT
                )

            if decipher_bytes_header['check_int_1'] \
                    != decipher_bytes_header['check_int_2']:
                warnings.warn('Cipher header check numbers do not match')

            initlist = []
            for i in range(num_keys):
                initlist.append(
                    PublicPrivateKeyPair(
                        public_key_list[i],
                        PrivateKey.from_byte_stream(decipher_byte_stream)
                    )
                )
                if initlist[i].public.header['key_type'] \
                        != initlist[i].private.header['key_type']:
                    warnings.warn(
                        f'Inconsistency between private and public '
                        f'key types for key {i}'
                    )
                if not all(
                    (
                        initlist[i].public.params[k] ==
                        initlist[i].private.params[k]
                    ) for k in (
                        initlist[i].public.params.keys() &
                        initlist[i].private.params.keys()
                    )
                ):
                    warnings.warn(
                        f'Inconsistency between private and public '
                        f'values for key {i}'
                    )

            decipher_padding = decipher_byte_stream.read()

            if (
                len(decipher_byte_stream.getvalue()) %
                    cipher_class.BLOCK_SIZE != 0
            ) or not (
                bytes(
                    range(1, 1 + cipher_class.BLOCK_SIZE)
                ).startswith(decipher_padding)
            ):
                warnings.warn('Incorrect padding at end of ciphertext')
        except ValueError as e:
            raise e
        except EOFError as e:
            raise ValueError('Premature EOF detected while parsing key.')
        except e:
            raise ValueError('Unexpected error condition reached.')

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

    @staticmethod
    def get_openssh_private_key_header() -> str:
        return '-----BEGIN OPENSSH PRIVATE KEY-----'

    OPENSSH_PRIVATE_KEY_HEADER = utils.readonly_static_property(
        get_openssh_private_key_header
    )

    @staticmethod
    def get_openssh_private_key_footer() -> str:
        return '-----END OPENSSH PRIVATE KEY-----'

    OPENSSH_PRIVATE_KEY_FOOTER = utils.readonly_static_property(
        get_openssh_private_key_footer
    )

    @staticmethod
    def get_wrap_col() -> int:
        return 70

    WRAP_COL = utils.readonly_static_property(get_wrap_col)

    @classmethod
    def from_string(
        cls: typing.Type[PrivateKeyListTypeVar],
        string: str,
        passphrase: typing.Optional[str] = None
    ) -> PrivateKeyListTypeVar:
        """Parses a private key list from a given string.

        Args:
            string
                The string from which to parse.
            passphrase
                The passphrase with which to decrypt the private byte string.
                If not provided, will be prompted for at standard input if
                needed.

        Returns:
            A :any:`PrivateKeyList` object containing the private key list.

        Raises:
            ValueError: The file does not have the expected PEM-style headers,
                the provided byte string is not an ``openssh-key-v1``
                key list, or the declared key count is negative.
            UserWarning: The check numbers in the decrypted private byte string
                do not match (likely due to an incorrect passphrase), the key
                type or parameter values of a private key do not match that of
                the corresponding public key in the list, or the padding bytes
                at the end of the decrypted private byte string are not as
                expected.
        """
        key_lines = string.splitlines()

        if key_lines[0] != cls.OPENSSH_PRIVATE_KEY_HEADER or \
                key_lines[-1] != cls.OPENSSH_PRIVATE_KEY_FOOTER:
            raise ValueError('Not an openssh private key')
        key_b64 = ''.join(key_lines[1:-1])
        key_bytes = base64.b64decode(key_b64)
        return cls.from_bytes(key_bytes, passphrase)

    @classmethod
    def from_list(
        cls: typing.Type[PrivateKeyListTypeVar],
        key_pair_list: typing.List[PublicPrivateKeyPair],
        cipher: str = 'none',
        kdf: str = 'none',
        kdf_options: typing.Optional[KDFOptions] = None
    ) -> PrivateKeyListTypeVar:
        """Constructs and initializes a private key list from a given list of
        key pairs and metadata.

        Args:
            key_pair_list
                The list of key pairs to add to the returned private key list.
            cipher
                The cipher type to add to the header of the private key list.
            kdf
                The key derivation function type to add to the header of the
                private key list.
            kdf_options
                The key derivation function parameters to add to the private
                key list.

        Returns:
            A :any:`PrivateKeyList` object containing the given list of key
            pairs and metadata.

        Raises:
            ValueError: The given list contains an item that is not a key pair.
        """
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
            kdf_options = NoneKDFOptions({})

        return cls(
            initlist,
            header=header,
            kdf_options=kdf_options
        )

    def pack_bytes(
        self,
        passphrase: typing.Optional[str] = None,
        include_indices: typing.Optional[typing.List[int]] = None,
        override_public_with_private: bool = True,
        retain_kdf_options_if_present: bool = False
    ) -> bytes:
        """Packs the private key list into a byte string.

        Args:
            passphrase
                The passphrase with which to encrypt the private byte string.
                If not provided, will be prompted for at standard input if
                needed.
            include_indices
                A list of indices into the private key list for the key pairs
                to include in the returned byte string.
            override_public_with_private
                If ``False``, packs the public bytes of each key from the
                public key of each key pair. If ``True``, ignores the public
                key of each key pair, instead packing the public bytes from the
                public parameters of the private key.
            retain_kdf_options_if_present
                If ``False``, packs the key derivation function parameters
                in this private key list object. If ``True``, generates and
                packs new key derivation function parameters.

        Returns:
            A byte string containing the private key list.

        Raises:
            IndexError: ``include_indices`` contains an index that is out of
                range for this private key list.
        """
        if isinstance(self.header, collections.abc.Mapping) \
                and 'cipher' in self.header and 'kdf' in self.header:
            cipher = self.header['cipher']
            kdf = self.header['kdf']
        else:
            cipher = 'none'
            kdf = 'none'

        if retain_kdf_options_if_present \
                and isinstance(self.kdf_options, collections.abc.Mapping):
            kdf_options = self.kdf_options
        else:
            kdf_options = get_kdf_options_class(kdf).generate_options()

        if include_indices is None:
            include_indices = list(range(len(self)))

        write_byte_stream = PascalStyleByteStream()

        kdf_options_write_byte_stream = PascalStyleByteStream()

        kdf_options_write_byte_stream.write_from_format_instructions_dict(
            get_kdf_options_class(kdf).FORMAT_INSTRUCTIONS_DICT,
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
            PrivateKeyList.HEADER_FORMAT_INSTRUCTIONS_DICT,
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
            PrivateKeyList.DECIPHER_BYTES_HEADER_FORMAT_INSTRUCTIONS_DICT,
            decipher_bytes_header
        )

        for i in include_indices:
            decipher_byte_stream.write(
                self[i].private.pack_private_bytes()
            )

        padding_length = (-len(decipher_byte_stream.getvalue())) \
            % get_cipher_class(cipher).BLOCK_SIZE
        padding_bytes = bytes(range(1, 1 + padding_length))
        decipher_byte_stream.write(padding_bytes)

        if kdf == 'none':
            passphrase = ''
        elif passphrase is None:
            passphrase = getpass.getpass('Key passphrase: ')

        cipher_class = get_cipher_class(cipher)
        cipher_bytes = cipher_class.encrypt(
            get_kdf_options_class(kdf)(kdf_options),
            passphrase,
            decipher_byte_stream.getvalue()
        )

        if issubclass(cipher_class, ConfidentialityIntegrityCipher):
            tag = cipher_bytes[-cipher_class.TAG_LENGTH:]
            cipher_bytes = cipher_bytes[:-cipher_class.TAG_LENGTH]

        write_byte_stream.write_from_format_instruction(
            PascalStyleFormatInstruction.BYTES,
            cipher_bytes
        )

        if issubclass(cipher_class, ConfidentialityIntegrityCipher):
            write_byte_stream.write(tag)

        return write_byte_stream.getvalue()

    def pack_string(
        self,
        passphrase: typing.Optional[str] = None,
        include_indices: typing.Optional[typing.List[int]] = None,
        override_public_with_private: bool = True,
        retain_kdf_options_if_present: bool = False
    ) -> str:
        """Packs the private key list into a string.

        Args:
            passphrase
                The passphrase with which to encrypt the private byte string.
                If not provided, will be prompted for at standard input if
                needed.
            include_indices
                A list of indices into the private key list for the key pairs
                to include in the returned byte string.
            override_public_with_private
                If ``False``, packs the public bytes of each key from the
                public key of each key pair. If ``True``, ignores the public
                key of each key pair, instead packing the public bytes from the
                public parameters of the private key.
            retain_kdf_options_if_present
                If ``False``, packs the key derivation function parameters
                in this private key list object. If ``True``, generates and
                packs new key derivation function parameters.

        Returns:
            A string containing the private key list.

        Raises:
            IndexError: ``include_indices`` contains an index that is out of
                range for this private key list.
        """
        text = self.OPENSSH_PRIVATE_KEY_HEADER + '\n'
        private_keys_bytes = self.pack_bytes(
            passphrase,
            include_indices,
            override_public_with_private,
            retain_kdf_options_if_present
        )
        private_keys_b64 = base64.b64encode(private_keys_bytes).decode()
        private_keys_wrapped = '\n'.join([
            (
                private_keys_b64[
                    i:
                    min(i + self.WRAP_COL, len(private_keys_b64))
                ]
            )
            for i in range(0, len(private_keys_b64), self.WRAP_COL)
        ])
        text += private_keys_wrapped
        text += '\n' + self.OPENSSH_PRIVATE_KEY_FOOTER + '\n'

        return text
