import pytest

from auditforge.core import registry


@pytest.fixture
def isolated_registry(monkeypatch):
    """Gives a test a fresh, empty primitive registry so it can register
    fakes without colliding with or polluting the real OS primitives."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    yield registry
