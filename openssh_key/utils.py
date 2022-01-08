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
        return typing.cast(
            ReadonlyStaticPropertyTypeVar,
            getattr(cls, self._getter.__name__)()
        )
