import pytest

from app.db import seed as seed_module


def test_demo_seed_is_skipped_when_disabled():
    class FailIfQueried:
        def query(self, *_args, **_kwargs):
            raise AssertionError("disabled demo seeding must not query the database")

    original = seed_module.SEED_DEMO_CLIENT
    seed_module.SEED_DEMO_CLIENT = False
    try:
        assert seed_module.seed_demo_client(FailIfQueried()) is None
    finally:
        seed_module.SEED_DEMO_CLIENT = original


def test_production_demo_seed_requires_explicit_key(monkeypatch):
    class EmptyQuery:
        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return None

    class EmptySession:
        def query(self, *_args, **_kwargs):
            return EmptyQuery()

    original_environment = seed_module.ENVIRONMENT
    original_enabled = seed_module.SEED_DEMO_CLIENT
    seed_module.ENVIRONMENT = "production"
    seed_module.SEED_DEMO_CLIENT = True
    monkeypatch.delenv("DEMO_API_KEY", raising=False)
    try:
        with pytest.raises(RuntimeError, match="DEMO_API_KEY is required"):
            seed_module.seed_demo_client(EmptySession())
    finally:
        seed_module.ENVIRONMENT = original_environment
        seed_module.SEED_DEMO_CLIENT = original_enabled
