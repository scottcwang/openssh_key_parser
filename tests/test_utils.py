from openssh_key import utils


def test_readonly_static_property_manual_get_call():
    def f():
        return 1
    p = utils.readonly_static_property(f)

    class C:
        @staticmethod
        def f():
            return 2
    assert p.__get__(C()) == 2
    assert p.__get__(None, C) == 2


def test_readonly_static_property_same_class():
    class C:
        @staticmethod
        def f():
            return 1
        p = utils.readonly_static_property(f)

    assert C().p == 1
    assert C.p == 1


def test_readonly_static_property_subclass_overrides():
    class C:
        @staticmethod
        def f():
            return 1
        p = utils.readonly_static_property(f)

    class D(C):
        @staticmethod
        def f():
            return 2

    assert D().p == 2
    assert D.p == 2


def test_readonly_static_property_subclass_inherits():
    class C:
        @staticmethod
        def f():
            return 1
        p = utils.readonly_static_property(f)

    class D(C):
        pass

    assert D().p == 1
    assert D.p == 1
