"""
Classes representing OpenSSH host and user certificates.
"""


import abc
import datetime
import enum
import types
import typing
import warnings

from .common import PublicKeyParams
from .dss import DSSPublicKeyParams
from .ecdsa import (ECDSA_NISTP256_PublicKeyParams,
                    ECDSA_NISTP384_PublicKeyParams,
                    ECDSA_NISTP521_PublicKeyParams)
from .ed25519 import Ed25519PublicKeyParams
from .rsa import RSAPublicKeyParams
from .sk import (
    SecurityKey_ECDSA_NISTP256_PublicKeyParams,
    SecurityKey_Ed25519_PublicKeyParams)
from openssh_key.pascal_style_byte_stream import (FormatInstructionsDict,
                                                  PascalStyleByteStream,
                                                  PascalStyleFormatInstruction)


class CertPrincipalType(enum.Enum):
    """
    The type of the principals that can authenticate using a certificate.
    """

    USER = 1
    """Denotes that this certificate's principals are users."""

    HOST = 2
    """Denotes that this certificate's principals are hosts."""


class CertOptionNameAndValidPrincipalTypes(typing.NamedTuple):
    """
    A certificate option's name and the types of certificate principals for
    which this certificate option is valid.
    """

    name: str
    """
    The certificate option's name.
    """

    valid_principal_types: typing.List[CertPrincipalType]
    """
    The types of certificate principals for which this certificate option is
    valid.
    """


class CertOption(enum.Enum):
    """
    A certificate option.
    """


class CertCriticalOption(CertOption):
    """
    An option that the validator must process for the certificate to be valid.
    """

    FORCE_COMMAND = CertOptionNameAndValidPrincipalTypes(
        'force-command', [CertPrincipalType.USER]
    )
    """
    A command to be executed on the remote machine when the session begins,
    overriding any that the user has specified as the command argument to
    ``ssh`` or the ``RemoteCommand`` option in ``ssh_config``.
    """

    SOURCE_ADDRESS = CertOptionNameAndValidPrincipalTypes(
        'source-address', [CertPrincipalType.USER]
    )
    """
    Comma-separated list of source addresses, in CIDR format, for which this
    certificate is valid for authentication.
    """

    VERIFY_REQUIRED = CertOptionNameAndValidPrincipalTypes(
        'verify-required', [CertPrincipalType.USER]
    )
    """
    If present, the private key should require user verification (equivalent to
    executing ``ssh-keygen`` with ``-O verify-required``). Not all FIDO
    authenticators support this option. OpenSSH presently supports only PIN
    verification.
    """


class CertExtension(CertOption):
    """
    An option that the validator may process if recognised.
    """

    NO_TOUCH_REQUIRED = CertOptionNameAndValidPrincipalTypes(
        'no-touch-required', [CertPrincipalType.USER]
    )
    """
    If present, the private key *does not* require the user to touch it
    (equivalent to executing ``ssh-keygen`` with ``-O no-touch-required``).
    """

    PERMIT_X11_FORWARDING = CertOptionNameAndValidPrincipalTypes(
        'permit-x11-forwarding', [CertPrincipalType.USER]
    )
    """
    If present, allows the user to enable X11 forwarding by specifying the
    ``-X`` option to ``ssh`` or the ``ForwardX11`` option in ``ssh_config``.
    """

    PERMIT_AGENT_FORWARDING = CertOptionNameAndValidPrincipalTypes(
        'permit-agent-forwarding', [CertPrincipalType.USER]
    )
    """
    If present, allows the user to enable agent forwarding by specifying the
    ``-A`` option to ``ssh`` or the ``ForwardAgent`` option in ``ssh_config``.
    """

    PERMIT_PORT_FORWARDING = CertOptionNameAndValidPrincipalTypes(
        'permit-port-forwarding', [CertPrincipalType.USER]
    )
    """
    If present, allows the user to enable local or remote port forwarding by
    specifying the ``-D``, ``-L``, or ``-R`` options to ``ssh`` or the
    ``DynamicForward``, ``LocalForward``, or ``RemoteForward`` options in
    ``ssh_config``.
    """

    PERMIT_PTY = CertOptionNameAndValidPrincipalTypes(
        'permit-pty', [CertPrincipalType.USER]
    )
    """
    If present, allows the user to request a pseudo-TTY by specifying the
    ``-t`` option to ``ssh`` or the ``RequestTTY`` option in ``ssh_config``.
    """

    PERMIT_USER_RC = CertOptionNameAndValidPrincipalTypes(
        'permit-user-rc', [CertPrincipalType.USER]
    )
    """
    If present, runs the user's ``~/.ssh/rc``, if it exists, once the user is
    authenticated; equivalent to setting the ``PermitUserRC`` option in
    ``sshd_config``.
    """


class CertPublicKeyParams(PublicKeyParams, abc.ABC):
    """
    The parameters comprising a certificate. OpenSSH supports certificates
    containing the following key types:

    * :py:class:`.rsa.RSAPublicKeyParams`
    * :py:class:`.dss.DSSPublicKeyParams`
    * :py:class:`.ecdsa.ECDSA_NISTP256_PublicKeyParams`
    * :py:class:`.ecdsa.ECDSA_NISTP384_PublicKeyParams`
    * :py:class:`.ecdsa.ECDSA_NISTP521_PublicKeyParams`
    * :py:class:`.ed25519.Ed25519PublicKeyParams`
    * :py:class:`.sk.SecurityKey_ECDSA_NISTP256_PublicKeyParams`
    * :py:class:`.sk.SecurityKey_Ed25519_PublicKeyParams`

    OpenSSH supports certificate authorities of the following key types:

    * :py:class:`.rsa.RSAPublicKeyParams`
    * :py:class:`.dss.DSSPublicKeyParams`
    * :py:class:`.ecdsa.ECDSA_NISTP256_PublicKeyParams`
    * :py:class:`.ecdsa.ECDSA_NISTP384_PublicKeyParams`
    * :py:class:`.ecdsa.ECDSA_NISTP521_PublicKeyParams`
    * :py:class:`.ed25519.Ed25519PublicKeyParams`

    The names and iteration order of parameters of a certificate is:

    * ``nonce``: A random string of arbitrary length provided by the
      certificate authority to prevent hash collisions (:any:`bytes`).
    * The parameters of the public key.
    * ``serial``: An optional serial number for the certificates issued by
      a certificate authority; `0` if the certificate authority does not
      record serial numbers (eight bytes).
    * ``type``: `1` if the certificate principals are users, or `2` if hosts
      (four bytes).
    * ``key_id``: A human-readable identifier for the key (:any:`str`).
    * ``valid_principals``: A series of strings identifying the principals:
      usernames if the certificate principals are users, or hostnames if hosts;
      empty if the certificate is valid for any principal (:any:`bytes`).
    * ``valid_after``: The number of seconds since the Unix epoch before which
      the certificate is invalid (eight bytes).
    * ``valid_before``: The number of seconds since the Unix epoch after which
      the certificate is invalid (eight bytes).
    * ``critical_options``: A series of strings that specify the options that
      the validator must process for this certificate to be valid. The strings
      alternate a unique ``name`` with the corresponding ``data``, and are
      sorted lexicographically by ``name`` (:any:`bytes`).
    * ``extensions``: A series of strings that specify the options that
      the validator may, but need not, process, for this certificate to be
      valid. The strings alternate a unique ``name`` with the corresponding
      ``data``, and are sorted lexicographically by ``name`` (:any:`bytes`).
    * ``reserved``: Reserved by OpenSSH (:any:`str`).
    * ``signature_key``: The parameters of the public key of the certificate
      authority (:any:`bytes`).
    * ``signature``: The signature of the certificate authority over the
      previous parameters (:any:`str`).

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A parameter value from the above list is missing from
            ``params`` or does not have the correct type.
    """

    @staticmethod
    @abc.abstractmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        """
        The type of the public key parameters that this certificate contains.
        """
        return PublicKeyParams

    __FORMAT_INSTRUCTIONS_DICT_SIGNED_BYTES_PREFIX: typing.ClassVar[FormatInstructionsDict] = {
        'nonce': PascalStyleFormatInstruction.BYTES,
    }

    __FORMAT_INSTRUCTIONS_DICT_SIGNED_BYTES_SUFFIX: typing.ClassVar[FormatInstructionsDict] = {
        'serial': '>Q',
        'type': '>I',
        'key_id': PascalStyleFormatInstruction.STRING,
        'valid_principals': PascalStyleFormatInstruction.BYTES,
        'valid_after': '>Q',
        'valid_before': '>Q',
        'critical_options': PascalStyleFormatInstruction.BYTES,
        'extensions': PascalStyleFormatInstruction.BYTES,
        'reserved': PascalStyleFormatInstruction.BYTES,
        'signature_key': PascalStyleFormatInstruction.BYTES,
    }

    __FORMAT_INSTRUCTIONS_DICT_SIGNATURE: typing.ClassVar[FormatInstructionsDict] = {
        'signature': PascalStyleFormatInstruction.BYTES,
    }

    @classmethod
    def get_format_instructions_dict(cls) -> FormatInstructionsDict:
        return types.MappingProxyType({
            **CertPublicKeyParams.__FORMAT_INSTRUCTIONS_DICT_SIGNED_BYTES_PREFIX,
            **cls.get_cert_base_public_key_class().get_format_instructions_dict(),
            **CertPublicKeyParams.__FORMAT_INSTRUCTIONS_DICT_SIGNED_BYTES_SUFFIX,
            **CertPublicKeyParams.__FORMAT_INSTRUCTIONS_DICT_SIGNATURE
        })

    def get_type(self) -> CertPrincipalType:
        """
        Returns the type of the principals that can authenticate using this
        certificate.
        """
        for t in CertPrincipalType:
            if self['type'] == t.value:
                return t
        raise ValueError('Not a valid certificate principal type')

    def set_type(self, t: CertPrincipalType) -> None:
        """
        Sets the type of the principals that can authenticate using this
        certificate.
        """
        self['type'] = t.value

    def get_valid_principals(self) -> typing.List[str]:
        """
        Returns the list of principals that can authenticate using this
        certificate.
        """
        return [
            principal['principal']
            for principal
            in PascalStyleByteStream(
                self['valid_principals']
            ).read_repeatedly_from_format_instructions_dict({
                'principal': PascalStyleFormatInstruction.STRING
            })
        ]

    @staticmethod
    def pack_list(
        l: typing.List[typing.Any],
        format_instruction: PascalStyleFormatInstruction
    ) -> bytes:
        """
        Packs a :any:`list` of items into a byte stream as per
        ``format_instruction``.

        Args:
            l
                The items to pack.
            format_instruction
                The format instruction.
        """
        stream = PascalStyleByteStream()
        stream.write_repeatedly_from_format_instructions_dict(
            {'item': format_instruction},
            [{'item': item} for item in l]
        )
        return stream.getvalue()

    def set_valid_principals(self, principals: typing.List[str]) -> None:
        """
        Sets the list of principals that can authenticate using this
        certificate.
        """
        self['valid_principals'] = self.pack_list(
            principals,
            PascalStyleFormatInstruction.STRING
        )

    def get_valid_after(self) -> datetime.datetime:
        """
        Returns the timestamp before which the certificate is invalid.
        """
        return datetime.datetime.fromtimestamp(self['valid_after'])

    def set_valid_after(self, t: datetime.datetime) -> None:
        """
        Sets the timestamp before which the certificate is invalid.
        """
        self['valid_after'] = int(t.timestamp())

    def get_valid_before(self) -> datetime.datetime:
        """
        Returns the timestamp after which the certificate is invalid.
        """
        return datetime.datetime.fromtimestamp(self['valid_before'])

    def set_valid_before(self, t: datetime.datetime) -> None:
        """
        Sets the timestamp after which the certificate is invalid.
        """
        self['valid_before'] = int(t.timestamp())

    def _get_option_values_dict(
        self,
        param_name: str
    ) -> typing.Mapping[str, bytes]:
        stream = PascalStyleByteStream(self[param_name])
        l = stream.read_repeatedly_from_format_instructions_dict({
            'option': PascalStyleFormatInstruction.STRING,
            'value': PascalStyleFormatInstruction.BYTES,
        })
        return_dict = {}
        for inner_dict in l:
            if inner_dict['option'] in return_dict:
                warnings.warn(
                    'Duplicate option ' + inner_dict['option']
                    + ' in ' + param_name
                )
            return_dict[inner_dict['option']] = inner_dict['value']
        return return_dict

    def _get_option_from_param(
        self,
        param_name: str,
        option: typing.Union[CertOption, str]
    ) -> typing.Optional[bytes]:
        if isinstance(option, CertOption) \
                and self.get_type() not in option.value.valid_principal_types:
            raise ValueError(
                'Option is not valid for the principal types of this certificate'
            )
        d = self._get_option_values_dict(param_name)
        for k in d:
            if (isinstance(option, CertOption) and option.value.name == k) \
                    or (isinstance(option, str) and option == k):
                return d[k]
        return None

    def get_critical_option(
        self,
        option: typing.Union[CertCriticalOption, str]
    ) -> typing.Optional[bytes]:
        """
        Returns the value of the specified critical option, or ``None`` if it
        does not exist.

        Args:
            option
                The critical option the value of which to return.

        Raises:
            ValueError: A ``CertCriticalOption`` is provided, but is not valid
                for the principal types of this certificate.
        """
        return self._get_option_from_param('critical_options', option)

    def get_extension_value(
        self,
        option: typing.Union[CertExtension, str]
    ) -> typing.Optional[bytes]:
        """
        Returns the value of the specified extension, or ``None`` if it does
        not exist.

        Args:
            option
                The extension the value of which to return.

        Raises:
            ValueError: A ``CertExtension`` is provided, but is not valid for
                the principal types of this certificate.
        """
        return self._get_option_from_param('extensions', option)

    @staticmethod
    def pack_options(
        d: typing.Mapping[str, bytes],
        format_instruction: PascalStyleFormatInstruction,
    ) -> bytes:
        """
        Packs a :any:`dict` of items into a byte stream, with the keys packed
        as :any:`str` and the values as per the provided ``format_instruction``.

        Args:
            d
                The mapping of items to pack.
            format_instruction
                The format instruction using which to pack the values.
        """
        l = [
            {
                'option': option,
                'value': d[option]
            }
            for option in sorted(d)
        ]
        stream = PascalStyleByteStream()
        stream.write_repeatedly_from_format_instructions_dict(
            {
                'option': PascalStyleFormatInstruction.STRING,
                'value': format_instruction
            },
            l
        )
        return stream.getvalue()

    def _set_option_for_param(
        self,
        param_name: str,
        option: typing.Union[CertOption, str],
        value: bytes,
    ) -> None:
        if isinstance(option, CertOption) \
                and self.get_type() not in option.value.valid_principal_types:
            raise ValueError(
                'Option ' + option.value.name
                + ' is not valid for the principal types of this certificate'
            )
        d = {**self._get_option_values_dict(param_name)}
        if isinstance(option, CertOption):
            d[option.value.name] = value
        else:
            d[option] = value
        self[param_name] = CertPublicKeyParams.pack_options(
            d,
            PascalStyleFormatInstruction.BYTES
        )

    def set_critical_option(
        self,
        option: typing.Union[CertCriticalOption, str],
        value: bytes,
    ) -> None:
        """
        Sets the value of the specified critical option.

        Args:
            option
                The critical option the value of which to set.
            value
                The value to set the critical option to.

        Raises:
            ValueError: A ``CertCriticalOption`` is provided, but is not valid
                for the principal types of this certificate.
        """
        self._set_option_for_param('critical_options', option, value)

    def set_extension_value(
        self,
        option: typing.Union[CertExtension, str],
        value: bytes,
    ) -> None:
        """
        Sets the value of the specified extension.

        Args:
            option
                The extension the value of which to set.
            value
                The value to set the extension to.

        Raises:
            ValueError: A ``CertExtension`` is provided, but is not valid for
                the principal types of this certificate.
        """
        self._set_option_for_param('extensions', option, value)

    def pack_signed_bytes(self) -> bytes:
        """
        Packs into a byte string the parameters of this certificate that would
        be signed by the certificate authority key to form the signature.

        Returns:
            A byte string containing the parameters of this certificate that
            would be signed by the certificate authority key to form the
            signature.
        """
        signed_byte_stream = PascalStyleByteStream()
        signed_byte_stream.write_from_format_instructions_dict(
            {
                **CertPublicKeyParams.__FORMAT_INSTRUCTIONS_DICT_SIGNED_BYTES_PREFIX,
                **self.get_cert_base_public_key_class().get_format_instructions_dict(),
                **CertPublicKeyParams.__FORMAT_INSTRUCTIONS_DICT_SIGNED_BYTES_SUFFIX,
            },
            self
        )
        return signed_byte_stream.getvalue()

    if typing.TYPE_CHECKING:  # pragma: no cover
        from openssh_key import key

    def get_signature_key(self) -> 'key.PublicKey':
        """
        Returns the public key of the certificate authority.

        Raises:
            UserWarning: The certificate authority is a certificate; this is
                not supported by OpenSSH.
        """
        from openssh_key import key
        signature_key = key.PublicKey.from_bytes(self['signature_key'])
        if isinstance(signature_key.params, CertPublicKeyParams):
            warnings.warn(
                'The certificate authority must not be a certificate'
            )
        return signature_key

    def set_signature_key(self, signature_key: 'key.PublicKey') -> None:
        """
        Sets the public key of the certificate authority to that specified.

        Args:
            public_key
                The public key of the certificate authority.

        Raises:
            ValueError: The certificate authority is a certificate; this is
                not supported by OpenSSH.
        """
        if isinstance(signature_key.params, CertPublicKeyParams):
            raise ValueError(
                'The certificate authority must not be a certificate'
            )
        self['signature_key'] = signature_key.pack_public_bytes()

    def check_params_are_valid(self) -> None:
        super().check_params_are_valid()
        self.get_cert_base_public_key_class().check_params_are_valid(self)

        if 'type' in self:
            try:
                self.get_type()
            except ValueError:
                warnings.warn('Not a valid certificate principal type')

        if 'valid_principals' in self \
                and isinstance(self['valid_principals'], bytes):
            try:
                self.get_valid_principals()
            except EOFError:
                warnings.warn('Invalid format for certificate principals list')

        if 'critical_options' in self \
                and isinstance(self['critical_options'], bytes):
            try:
                self._get_option_values_dict('critical_options')
            except EOFError:
                warnings.warn('Invalid format for critical options list')

        if 'extensions' in self \
                and isinstance(self['extensions'], bytes):
            try:
                self._get_option_values_dict('extensions')
            except EOFError:
                warnings.warn('Invalid format for extensions list')

        if 'signature_key' in self and isinstance(self['signature_key'], bytes):
            try:
                self.get_signature_key()
            except (ValueError, EOFError, TypeError):
                warnings.warn('Certificate authority is not a valid key')


class Cert_RSA_PublicKeyParams(CertPublicKeyParams, RSAPublicKeyParams):
    """
    The parameters comprising a certificate for an RSA public key.
    """

    @staticmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return RSAPublicKeyParams


class Cert_Ed25519_PublicKeyParams(CertPublicKeyParams, Ed25519PublicKeyParams):
    """
    The parameters comprising a certificate for an Ed25519 public key.
    """

    @staticmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return Ed25519PublicKeyParams


class Cert_DSS_PublicKeyParams(CertPublicKeyParams, DSSPublicKeyParams):
    """
    The parameters comprising a certificate for a DSS public key.
    """

    @staticmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return DSSPublicKeyParams


class Cert_ECDSA_NISTP256_PublicKeyParams(CertPublicKeyParams, ECDSA_NISTP256_PublicKeyParams):
    """
    The parameters comprising a certificate for an ECDSA key on the
    ``nistp256`` curve.
    """

    @staticmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return ECDSA_NISTP256_PublicKeyParams


class Cert_ECDSA_NISTP384_PublicKeyParams(CertPublicKeyParams, ECDSA_NISTP384_PublicKeyParams):
    """
    The parameters comprising a certificate for an ECDSA key on the
    ``nistp384`` curve.
    """

    @staticmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return ECDSA_NISTP384_PublicKeyParams


class Cert_ECDSA_NISTP521_PublicKeyParams(CertPublicKeyParams, ECDSA_NISTP521_PublicKeyParams):
    """
    The parameters comprising a certificate for an ECDSA key on the
    ``nistp521`` curve.
    """

    @staticmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return ECDSA_NISTP521_PublicKeyParams


class Cert_SecurityKey_Ed25519_PublicKeyParams(CertPublicKeyParams, SecurityKey_Ed25519_PublicKeyParams):
    """
    The parameters comprising a certificate for an Ed25519 public key that
    corresponds to a private key stored on a security key.
    """

    @staticmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return SecurityKey_Ed25519_PublicKeyParams


class Cert_SecurityKey_ECDSA_NISTP256_PublicKeyParams(CertPublicKeyParams, SecurityKey_ECDSA_NISTP256_PublicKeyParams):
    """
    The parameters comprising a certificate for an ECDSA key that
    corresponds to a private key stored on a security key.
    """

    @staticmethod
    def get_cert_base_public_key_class() -> typing.Type[PublicKeyParams]:
        return SecurityKey_ECDSA_NISTP256_PublicKeyParams
