def is_abstract(cls):
    """
    Returns whether ``cls`` is an abstract class.
    """
    return hasattr(cls, '__abstractmethods__') \
        and len(cls.__abstractmethods__) != 0
