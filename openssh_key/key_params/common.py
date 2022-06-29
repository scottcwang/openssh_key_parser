"""Classes representing public- and private-key parameters for keys of various
cryptosystems.
"""

import abc
import typing

from openssh_key.pascal_style_byte_stream import PascalStyleDict, ValuesDict

PublicKeyParamsTypeVar = typing.TypeVar(
    'PublicKeyParamsTypeVar',
    bound='PublicKeyParams'
)


class ConversionFunctions(typing.NamedTuple):
    """Functions to convert :any:`typing.Mapping`, representing parameter
    values, to an object of a certain type, and *vice versa*.
    """
    object_to_mapping: typing.Callable[
        [typing.Any],
        typing.Optional[ValuesDict]
    ]
    """Functions to convert an object of a certain type to a
    :any:`typing.Mapping` representing the parameter values in the object.
    """

    mapping_to_object: typing.Callable[
        [ValuesDict],
        typing.Any
    ]
    """Functions to convert a :any:`typing.Mapping` containing parameter
    values to an object of a certain type.
    """


class PublicKeyParams(PascalStyleDict):
    """The parameters comprising a key.

    The names and iteration order of parameters of *public* keys recognized by
    implementations of the Secure Shell (SSH) protocol are as specified in
    `RFC 4253 <https://tools.ietf.org/html/rfc4253#section-6.6>`_.

    Args:
        params
            The values with which to initialize this parameters object. All
            given values are saved, even those that do not exist in the format
            instructions for this key type.

    Raises:
        UserWarning: A value in ``params`` is missing or does not have a type
            that matches the format instructions for this key type.
    """

    @classmethod
    def convert_from(
        cls,
        key_object: typing.Any
    ) -> 'PublicKeyParams':
        """Constructs and initializes a parameters object for this key type
        from attributes contained in the given object.

        This classmethod searches :any:`conversion_functions` for a class that
        is a superclass of ``key_object``. If one is found, it returns the
        parameters object from the :any:`typing.Mapping` returned by the
        corresponding :any:`object_to_mapping` function. Otherwise, it searches
        its subclasses' :any:`conversion_functions`, traversing pre-order.

        Args:
            key_object
                An object containing key parameter values.

        Raises:
            ValueError: ``key_object`` is not of a supported type,
                or it does not contain the attributes necessary to construct
                a parameters object of this class.
        """
        params_dict: typing.Optional[ValuesDict] = None
        for k, v in cls.conversion_functions().items():
            if isinstance(key_object, k):
                params_dict = v.object_to_mapping(key_object)
                break
        if params_dict is None:
            for subcls in cls.__subclasses__():
                try:
                    params_dict = dict(subcls.convert_from(key_object))
                except ValueError:
                    pass
                if params_dict is not None:
                    break
        if params_dict is not None:
            return cls({
                k: params_dict[k]
                for k in cls.FORMAT_INSTRUCTIONS_DICT
            })
        raise ValueError(
            'key_object is not of a supported type, or does not contain the attributes '
            'necessary to construct a parameters object of this class'
        )

    @classmethod
    def conversion_functions(
        cls
    ) -> typing.Mapping[
        typing.Type[typing.Any],
        ConversionFunctions
    ]:
        """Functions to extract parameter values dicts for supported types of
        key objects.

        Returns:
            A :py:class:`typing.Mapping` from types of key objects to functions
            that take key objects of that type and return parameter values.
        """
        return {}

    def convert_to(
        self,
        destination_class: typing.Type[typing.Any]
    ) -> typing.Any:
        """Creates and initializes an object of the given type containing the
        values of this parameters object.

        This method searches :any:`conversion_functions` for a class that
        is a subclass of ``key_object``. If one is found, it passes this
        parameters object to the corresponding :any:`mapping_to_object`.
        Otherwise, it searches its superclasses' :any:`conversion_functions`
        in the same way, in method resolution order, up to and including
        :any:`PublicKeyParams`.

        Args:
            destination_class
                The type of the object to which the values of this parameters
                object are to be converted.

        Raises:
            ValueError: ``destination_class`` is not a class, or converting
                this parameters object to an object of type ``destination_class``
                is not supported.
            ImportError: ``destination_class`` cannot be imported.
        """
        if not isinstance(destination_class, type):
            raise ValueError('destination_class must be a class')
        for supercls in self.__class__.__mro__:
            if not issubclass(supercls, PublicKeyParams):
                break
            for candidate_class in supercls.conversion_functions():
                if issubclass(candidate_class, destination_class):
                    return supercls.conversion_functions()[
                        candidate_class
                    ].mapping_to_object(self)
        raise ValueError(  # pragma: no cover
            'Converting this parameters object to an object of type '
            + destination_class.__name__
            + ' is not supported'
        )


PrivateKeyParamsTypeVar = typing.TypeVar(
    'PrivateKeyParamsTypeVar',
    bound='PrivateKeyParams'
)


class PrivateKeyParams(PublicKeyParams):
    """The parameters comprising a private key, a superset of those parameters
    comprising a public key (:any:`PublicKeyParams`).

    The names and iteration order of parameters of *private* keys recognized by
    implementations of the Secure Shell (SSH) protocol are as specified for
    the ``SSH_AGENTC_ADD_IDENTITY`` message of the
    `ssh-agent protocol <https://tools.ietf.org/html/draft-miller-ssh-agent-03#section-4.2>`_.
    """

    @classmethod
    @abc.abstractmethod
    def generate_private_params(
        cls: typing.Type[PrivateKeyParamsTypeVar],
        **kwargs: typing.Any
    ) -> PrivateKeyParamsTypeVar:
        """Constructs and initializes a parameters object with generated
        values.

        Args:
            kwargs
                Keyword arguments consumed to generate parameter values.

        Returns:
            A private key parameters object with generated values valid for
            a private key of this type.
        """
        return cls({})
