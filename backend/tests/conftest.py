import pytest
import redis as redis_lib
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings
from tests import isolation

# --- Fail-closed isolation (see tests/isolation.py) ------------------------
# Applied at import time, BEFORE any other `app` module is imported: the
# DB engine (app/database.py), Celery broker (app/celery_app.py), rate-limit
# storage (app/services/rate_limit.py) and lockout client
# (app/services/account_lockout.py) all bind to settings when imported.
# Repointing settings here means the whole test process -- including
# executors that open database.SessionLocal() directly -- can only ever
# reach the isolated test database and test Redis DB, never development
# data or the live Celery broker.
try:
    _TEST_DATABASE_URL = isolation.validated_test_database_url(
        settings.test_database_url, settings.database_url, settings.environment
    )
    _TEST_REDIS_URL = isolation.isolated_test_redis_url(settings.redis_url, settings.test_redis_url)
    # Last, and only once the URL rules pass: a read-only check that the
    # database actually reached is explicitly marked as disposable.
    isolation.verify_test_database_marker(_TEST_DATABASE_URL)
except isolation.UnsafeTestConfiguration as exc:
    pytest.exit(f"Refusing to run the test suite: {exc}", returncode=pytest.ExitCode.USAGE_ERROR)

# Where the app would have gone without the overrides -- recorded
# (host/port/name only, no credentials) so tests can prove the redirect
# below actually took effect.
LIVE_DATABASE_TARGET = isolation.database_target(settings.database_url)
LIVE_REDIS_TARGET = isolation.redis_target(settings.redis_url)

settings.database_url = _TEST_DATABASE_URL
settings.redis_url = _TEST_REDIS_URL

from app.database import get_db  # noqa: E402 -- must follow the isolation overrides above
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402

test_engine = create_engine(_TEST_DATABASE_URL)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

_network_guard = isolation.NetworkGuard(allowed_hostnames=isolation.allowed_test_hostnames(_TEST_REDIS_URL))


@pytest.fixture(scope="session", autouse=True)
def _block_real_network_access():
    """Ordinary test runs must never reach the real network -- no real
    DNS, no connections beyond loopback test servers and the test Redis.
    See isolation.NetworkGuard."""
    with pytest.MonkeyPatch.context() as session_monkeypatch:
        _network_guard.install(session_monkeypatch)
        yield


@pytest.fixture(autouse=True)
def _fail_on_real_network_access():
    """Fails any test that tried to reach the real network, even if the
    code under test swallowed the RealNetworkAccessBlocked it got."""
    _network_guard.blocked_attempts.clear()
    yield
    if _network_guard.blocked_attempts:
        attempts = "; ".join(_network_guard.blocked_attempts)
        _network_guard.blocked_attempts.clear()
        pytest.fail(f"test attempted real network access (blocked): {attempts}", pytrace=False)


@pytest.fixture
def network_guard():
    """The session's NetworkGuard, for tests that verify the guard itself
    (they must clear blocked_attempts for anything they trigger on purpose)."""
    return _network_guard


@pytest.fixture
def live_targets():
    """Where DATABASE_URL/REDIS_URL pointed before the isolation overrides
    -- (host, port, name/index) only, never credentials. Exposed as a
    fixture because test modules must never import conftest directly."""
    return {"database": LIVE_DATABASE_TARGET, "redis": LIVE_REDIS_TARGET}


@pytest.fixture(autouse=True)
def _enable_test_only_discovery_providers(monkeypatch):
    """The `stub` provider is unavailable unless explicitly enabled. Many
    pipeline tests rely on it as a deterministic provider, so each test
    starts with it enabled -- tests of the disabled behavior turn it back
    off with their own monkeypatch."""
    monkeypatch.setattr(settings, "enable_test_discovery_providers", True)


@pytest.fixture(scope="session", autouse=True)
def _create_schema():
    isolation.assert_is_test_database(test_engine.url)
    Base.metadata.create_all(bind=test_engine)
    yield
    isolation.assert_is_test_database(test_engine.url)
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """slowapi's rate-limit counters live in Redis, which — unlike
    Postgres — is NOT truncated between tests by _clean_tables. Without
    this, cumulative /auth/login (etc.) calls across the many test files
    that authenticate would eventually trip the real 5/minute limit on
    tests that have nothing to do with rate limiting, causing flaky
    unrelated failures. Flushes only the isolated test Redis DB (see the
    overrides at the top of this file) -- re-checked here so it can never
    flush the live Celery broker's DB.
    """
    isolation.assert_not_live_redis(settings.redis_url, LIVE_REDIS_TARGET)
    client = redis_lib.Redis.from_url(settings.redis_url)
    client.flushdb()
    yield


@pytest.fixture(autouse=True)
def _clean_tables():
    """Truncate all tables between tests instead of recreating the schema
    each time — much faster against a real Postgres instance.
    """
    yield
    isolation.assert_is_test_database(test_engine.url)
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
    real Celery worker use — no request-scoped session to borrow there).
    The isolation overrides at the top of this file already point
    app.database at the test database for the whole run; this keeps such
    sessions on the very same TestSessionLocal the `db` fixture uses.
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
