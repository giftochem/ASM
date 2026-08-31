"""Regression tests for Step 7A remediation, finding H-2 item 10: the
app must fail closed when a required secret is missing -- not just when
the env var is completely absent (pydantic's own required-field check
already covers that), but also when it's present-but-empty, which the
bare `str` type annotation alone accepts silently. Verified this gap
existed empirically (via a live container run) before fixing it.
"""

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_empty_jwt_secret_key_is_rejected():
    with pytest.raises(ValidationError, match="jwt_secret_key"):
        Settings(jwt_secret_key="", database_url="postgresql://user:pass@localhost/db")


def test_whitespace_only_jwt_secret_key_is_rejected():
    with pytest.raises(ValidationError, match="jwt_secret_key"):
        Settings(jwt_secret_key="   ", database_url="postgresql://user:pass@localhost/db")


def test_empty_database_url_is_rejected():
    with pytest.raises(ValidationError, match="database_url"):
        Settings(jwt_secret_key="a-real-looking-secret-value", database_url="")


def test_real_looking_values_are_accepted():
    settings = Settings(
        jwt_secret_key="a-real-looking-secret-value",
        database_url="postgresql://user:pass@localhost/db",
    )
    assert settings.jwt_secret_key == "a-real-looking-secret-value"
    assert settings.database_url == "postgresql://user:pass@localhost/db"
