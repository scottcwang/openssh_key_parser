"""
Utility classes and methods.
"""

import collections
import typing


def is_abstract(cls: typing.Type[typing.Any]) -> bool:
    """
    Returns whether ``cls`` is an abstract class.
    """
    return hasattr(cls, '__abstractmethods__') \
        and len(cls.__abstractmethods__) != 0


ReadonlyStaticPropertyTypeVar = typing.TypeVar(
    'ReadonlyStaticPropertyTypeVar'
)


class readonly_static_property(
    typing.Generic[ReadonlyStaticPropertyTypeVar]
):
    """
    A static property that calls the first method in an object's MRO of the
    same name as that of the provided method.

    Args:
        getter
            The method the name of which is that of the method to call.
    """

    def __init__(
        self,
        getter: typing.Union[
            typing.Callable[[], ReadonlyStaticPropertyTypeVar],
            typing.Callable[[typing.Type[typing.Any]], ReadonlyStaticPropertyTypeVar]
        ]
    ) -> None:
        self._getter = getter

    def __get__(
        self,
        obj: typing.Any,
        cls: typing.Optional[typing.Type[typing.Any]] = None
    ) -> ReadonlyStaticPropertyTypeVar:
        if cls is None:
            cls = type(obj)
        f = self._getter
        if isinstance(f, (staticmethod, classmethod)):
            f = f.__func__
        return typing.cast(
            ReadonlyStaticPropertyTypeVar,
            getattr(cls, f.__name__)()
        )


# https://github.com/python/mypy/issues/5264
if typing.TYPE_CHECKING:  # pragma: no cover
    BaseDict = collections.UserDict[  # pylint: disable=unsubscriptable-object
        str, typing.Any
    ]
else:
    BaseDict = collections.UserDict
