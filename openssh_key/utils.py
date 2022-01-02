import typing


def is_abstract(cls: typing.Type[typing.Any]) -> bool:
    """
    Returns whether ``cls`` is an abstract class.
    """
    return hasattr(cls, '__abstractmethods__') \
        and len(cls.__abstractmethods__) != 0


class readonly_static_property():
    def __init__(self, getter_name: str) -> None:
        self._getter_name = getter_name

    def __get__(
        self,
        obj: typing.Any,
        cls: typing.Optional[typing.Type[typing.Any]]=None
    ) -> typing.Any:
        if cls is None:
            cls = type(obj)
        return getattr(cls, self._getter_name)()
