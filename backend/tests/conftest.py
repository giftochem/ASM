import redis as redis_lib
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from app.database import get_db
from app.main import app
from app.models import Base

test_engine = create_engine(settings.test_database_url or settings.database_url)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def _create_schema():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """slowapi's rate-limit counters live in Redis, which — unlike
    Postgres — is NOT truncated between tests by _clean_tables. Without
    this, cumulative /auth/login (etc.) calls across the many test files
    that authenticate would eventually trip the real 5/minute limit on
    tests that have nothing to do with rate limiting, causing flaky
    unrelated failures. Flushing the whole Redis DB is safe here: this
    Redis instance is dev/test-only infrastructure (Celery broker +
    rate-limit storage), not a store of anything that needs to survive
    across test boundaries. Safe for test_celery_integration.py too,
    since it flushes only at clean before/after-test boundaries, never
    mid-test against the live worker.
    """
    client = redis_lib.Redis.from_url(settings.redis_url)
    client.flushdb()
    yield


@pytest.fixture(autouse=True)
def _clean_tables():
    """Truncate all tables between tests instead of recreating the schema
    each time — much faster against a real Postgres instance.
    """
    yield
    with test_engine.begin() as conn:
        table_names = ", ".join(f'"{t.name}"' for t in reversed(Base.metadata.sorted_tables))
        conn.execute(text(f"TRUNCATE {table_names} RESTART IDENTITY CASCADE"))


@pytest.fixture
def db() -> Session:
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _override_get_db(db):
    def _get_test_db():
        yield db

    app.dependency_overrides[get_db] = _get_test_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def executor_uses_test_db(monkeypatch):
    """scan_executor.execute_scan opens its own DB session (it has to, for
    real Celery worker use — no request-scoped session to borrow there),
    which by default resolves against the dev database. Any test that
    invokes execution — directly, or indirectly via a Celery task running
    in eager mode — needs this, or it'll silently operate on the wrong
    database.
    """
    monkeypatch.setattr("app.database.SessionLocal", TestSessionLocal)
    yield


@pytest.fixture
def eager_celery(monkeypatch, executor_uses_test_db):
    """Opt-in synchronous Celery execution for tests that need a
    deterministic, immediate result (e.g. the Phase 1-derived scan
    pipeline tests). NOT a global default — celery_app.conf.task_always_eager
    defaults to False, matching real deployment behavior, and only tests
    that explicitly request this fixture get eager mode.
    """
    from app.celery_app import celery_app

    monkeypatch.setattr(celery_app.conf, "task_always_eager", True)
    yield


def _headers_from_client_cookies(client) -> dict:
    """Auth is cookie-based now (httpOnly access/refresh + a readable
    csrf_token, see docs/auth-cookie-model.md) — there is no token in a
    JSON response body to extract anymore. This builds a `headers` dict
    carrying a literal `Cookie` header (so it works as a normal HTTP
    header regardless of whether it came from TestClient's own jar or was
    set explicitly — the server doesn't care) plus X-CSRF-Token, then
    clears the shared `client`'s cookie jar so a second
    register_user()/login_as() call in the same test starts from a clean
    slate instead of overwriting the first identity's session.

    This is deliberately shaped so existing call sites that already do
    `client.post(..., headers=headers)` continue to work completely
    unchanged — only auth fixtures needed to change, not every test.
    """
    access_token = client.cookies.get("access_token")
    refresh_token = client.cookies.get("refresh_token")
    csrf_token = client.cookies.get("csrf_token")
    assert access_token and refresh_token and csrf_token, "expected all three auth cookies to be set"
    headers = {
        "Cookie": f"access_token={access_token}; refresh_token={refresh_token}; csrf_token={csrf_token}",
        "X-CSRF-Token": csrf_token,
    }
    client.cookies.clear()
    return headers


@pytest.fixture
def register_user(client):
    """Registers a new org + admin user and returns headers carrying that
    session (see _headers_from_client_cookies) — used by tests that need
    an authenticated caller without re-testing registration itself (that's
    covered in test_auth.py).
    """

    def _register(
        org_name: str = "Test Org",
        email: str = "admin@example.com",
        password: str = "correct-horse-battery",
        full_name: str = "Test Admin",
    ) -> dict:
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": org_name,
                "email": email,
                "password": password,
                "full_name": full_name,
            },
        )
        assert resp.status_code == 201, resp.text
        return _headers_from_client_cookies(client)

    return _register


@pytest.fixture
def login_as(client):
    """Logs in an already-existing user and returns headers carrying that
    session — the cookie-auth equivalent of the old "grab access_token out
    of the login response body" pattern several tests used to build a
    second identity mid-test.
    """

    def _login(email: str, password: str) -> dict:
        resp = client.post("/auth/login", data={"username": email, "password": password})
        assert resp.status_code == 200, resp.text
        return _headers_from_client_cookies(client)

    return _login
