import pytest

from auditforge.core.registry import (
    ApplyOutcome,
    Primitive,
    ProbeResult,
    compare_value,
    get,
    is_registered,
    register,
)


class _EchoPrimitive(Primitive):
    name = "test_echo"

    def probe(self, params):
        return ProbeResult(value=params.get("value"))

    def apply(self, params, expected_value):
        return ApplyOutcome(previous_value=None, new_value=expected_value)

    def rollback(self, params, change):
        return True


class TestCompareValue:
    def test_plain_equality(self):
        assert compare_value(5, 5) is True
        assert compare_value(5, 6) is False

    def test_string_case_insensitive(self):
        assert compare_value("Enabled", "enabled") is True
        assert compare_value(" Enabled ", "enabled") is True

    def test_bool_coercion(self):
        assert compare_value(1, True) is True
        assert compare_value(0, False) is True
        assert compare_value(1, False) is False

    def test_min_only(self):
        assert compare_value(15, {"min": 14}) is True
        assert compare_value(13, {"min": 14}) is False

    def test_max_only(self):
        assert compare_value(3, {"max": 5}) is True
        assert compare_value(6, {"max": 5}) is False

    def test_min_and_max_range(self):
        assert compare_value(5, {"min": 1, "max": 10}) is True
        assert compare_value(0, {"min": 1, "max": 10}) is False
        assert compare_value(11, {"min": 1, "max": 10}) is False

    def test_one_of(self):
        assert compare_value("Manual", {"one_of": ["Manual", "Automatic"]}) is True
        assert compare_value("Disabled", {"one_of": ["Manual", "Automatic"]}) is False

    def test_not(self):
        assert compare_value("Enabled", {"not": "Disabled"}) is True
        assert compare_value("Disabled", {"not": "Disabled"}) is False

    def test_min_max_reject_non_numeric(self):
        assert compare_value(None, {"min": 1}) is False
        assert compare_value("not-a-number", {"max": 5}) is False


class TestRegistry:
    def test_register_and_get(self, isolated_registry):
        register(_EchoPrimitive)
        assert is_registered("test_echo")
        prim = get("test_echo")
        assert isinstance(prim, _EchoPrimitive)

    def test_register_instantiates_class_decorator(self, isolated_registry):
        # The @register decorator is applied directly to a class in every
        # controls/<os>/primitives.py module; this guards the exact bug
        # that was found and fixed during Windows primitive testing (the
        # registry must store an INSTANCE, not the class itself).
        register(_EchoPrimitive)
        prim = get("test_echo")
        result = prim.probe({"value": 42})
        assert result.value == 42

    def test_duplicate_registration_raises(self, isolated_registry):
        register(_EchoPrimitive)
        with pytest.raises(ValueError, match="duplicate"):
            register(_EchoPrimitive)

    def test_unknown_primitive_raises_keyerror(self, isolated_registry):
        with pytest.raises(KeyError):
            get("does_not_exist")

    def test_default_compare_uses_compare_value(self, isolated_registry):
        register(_EchoPrimitive)
        prim = get("test_echo")
        assert prim.compare(15, {"min": 14}) is True
        assert prim.compare(10, {"min": 14}) is False
