"""The test suite can only touch isolated test resources and never the
real network (see tests/isolation.py and the overrides at the top of
tests/conftest.py).

Two kinds of checks: the guard functions, exercised with synthetic URLs
(never a real development/production database or Redis -- the only real
resource touched is the isolated test database, read-only), and
assertions about THIS running session, proving the app's engine, Celery
broker and Redis clients really were redirected and the network guard is
active.
"""

import socket

import dns.resolver
import pytest
from sqlalchemy.engine import make_url

from app import database
from app.celery_app import celery_app
from app.config import settings
from app.services import account_lockout, rate_limit
from tests import isolation

_LIVE_DB_URL = "postgresql+psycopg2://asm:s3cret-live-pw@db:5432/asm"
_TEST_DB_URL = "postgresql+psycopg2://asm:s3cret-test-pw@db:5432/asm_test"


# --- environment allowlist ----------------------------------------------------


@pytest.mark.parametrize("environment", ["production", "Production", " prod ", "staging", "qa", "", None])
def test_suite_refuses_any_environment_outside_the_allowlist(environment):
    with pytest.raises(isolation.UnsafeTestConfiguration, match="only runs with one of"):
        isolation.validated_test_database_url(_TEST_DB_URL, _LIVE_DB_URL, environment)


@pytest.mark.parametrize("environment", ["development", "test", " Development ", "TEST"])
def test_suite_accepts_allowlisted_environments(environment):
    assert isolation.validated_test_database_url(_TEST_DB_URL, _LIVE_DB_URL, environment) == _TEST_DB_URL


# --- database URL rules (synthetic URLs only) ----------------------------------


@pytest.mark.parametrize("missing", [None, ""])
def test_missing_test_database_url_is_refused(missing):
    with pytest.raises(isolation.UnsafeTestConfiguration, match="TEST_DATABASE_URL is not set"):
        isolation.validated_test_database_url(missing, _LIVE_DB_URL, "development")


@pytest.mark.parametrize(
    "name",
    ["asm", "asm_latest", "contest", "asmtest", "test", "asm_test_old", "ASM_TEST", "asm-test", "test_asm"],
)
def test_test_database_must_follow_the_strict_name_test_convention(name):
    with pytest.raises(isolation.UnsafeTestConfiguration, match="'<name>_test'") as excinfo:
        isolation.validated_test_database_url(
            f"postgresql+psycopg2://asm:s3cret-test-pw@db:5432/{name}", _LIVE_DB_URL, "development"
        )
    assert "s3cret" not in str(excinfo.value)


@pytest.mark.parametrize("name", ["asm_test", "x1_test", "ci_run_42_test"])
def test_strictly_named_test_databases_are_accepted(name):
    url = f"postgresql+psycopg2://asm:pw@db:5432/{name}"
    assert isolation.validated_test_database_url(url, _LIVE_DB_URL, "development") == url


@pytest.mark.parametrize(
    "live_url",
    [
        "postgresql+psycopg2://asm:pw-one@db:5432/shared_test",  # same host
        "postgresql+psycopg2://asm:pw-one@172.18.0.2:5432/shared_test",  # IP alias of the same server
        "postgresql+psycopg2://asm:pw-one@localhost:6543/shared_test",  # port-forward alias
        "postgresql+psycopg2://other:pw-one@DB.internal:5432/shared_test",  # different hostname entirely
    ],
)
def test_same_database_name_is_refused_whatever_the_hostnames(live_url):
    """Hostnames, IPs and ports can all alias one server, so two URLs that
    name the same database are refused without trusting any host
    comparison."""
    with pytest.raises(isolation.UnsafeTestConfiguration, match="could be the same") as excinfo:
        isolation.validated_test_database_url(
            "postgresql+psycopg2://asm:pw-two@db:5432/shared_test", live_url, "development"
        )
    assert "pw-one" not in str(excinfo.value) and "pw-two" not in str(excinfo.value)


def test_unparseable_url_is_refused_without_echoing_it():
    with pytest.raises(isolation.UnsafeTestConfiguration) as excinfo:
        isolation.validated_test_database_url("not a url ::: s3cret-in-garbage", _LIVE_DB_URL, "development")
    assert "s3cret" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None


def test_destructive_operations_refuse_a_database_not_named_like_a_test_database():
    with pytest.raises(RuntimeError, match="non-test database"):
        isolation.assert_is_test_database(make_url(_LIVE_DB_URL))
    with pytest.raises(RuntimeError, match="non-test database"):
        isolation.assert_is_test_database(make_url("postgresql+psycopg2://asm:pw@db:5432/asm_latest"))
    isolation.assert_is_test_database(make_url(_TEST_DB_URL))


# --- explicit "disposable test database" marker ---------------------------------
# Only the isolated test database is ever connected to here (read-only).


def test_the_isolated_test_database_carries_the_marker():
    isolation.verify_test_database_marker(settings.database_url)  # settings now points at the test DB


def test_a_database_without_the_expected_marker_is_refused():
    """Same real test database, but demanding a marker it doesn't carry --
    proves a reachable, correctly named database is still refused unless
    it was explicitly provisioned as disposable."""
    with pytest.raises(isolation.UnsafeTestConfiguration, match="not marked as a disposable test database"):
        isolation.verify_test_database_marker(settings.database_url, expected_marker="some-other-marker")


def test_an_unreachable_test_database_is_refused_without_echoing_credentials():
    with pytest.raises(isolation.UnsafeTestConfiguration, match="could not verify") as excinfo:
        # Loopback port 1: nothing listens there, so this fails fast and locally.
        isolation.verify_test_database_marker("postgresql+psycopg2://asm:s3cret-pw@127.0.0.1:1/asm_test")
    assert "s3cret" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None


# --- Redis rules (synthetic URLs only) ------------------------------------------


def test_redis_defaults_to_a_dedicated_db_index_on_the_same_server():
    derived = isolation.isolated_test_redis_url("redis://redis:6379/0")
    assert derived == "redis://redis:6379/15"
    assert isolation.redis_target(derived) == ("redis", 6379, 15)


def test_explicit_test_redis_url_is_honored():
    assert isolation.isolated_test_redis_url("redis://redis:6379/0", "redis://redis:6379/9") == "redis://redis:6379/9"


@pytest.mark.parametrize(
    ("live", "explicit"),
    [
        ("redis://redis:6379/15", None),  # derived index collides with the live one
        ("redis://redis:6379/0", "redis://REDIS:6379/0"),  # same server, case variant
        ("redis://redis:6379", "redis://redis:6379/0"),  # no path means DB 0
        ("redis://redis:6379/0", "redis://172.18.0.3:6379/0"),  # IP alias of the same server
        ("redis://localhost:6379/0", "redis://127.0.0.1:6380/0"),  # port-forward alias
        ("redis://redis:6379/0", "redis://other-host:6379/0"),  # host comparison is never trusted
    ],
)
def test_test_redis_with_the_live_db_index_is_refused_whatever_the_host(live, explicit):
    with pytest.raises(isolation.UnsafeTestConfiguration, match="same index REDIS_URL uses"):
        isolation.isolated_test_redis_url(live, explicit)


def test_redis_db_selected_by_query_string_is_refused():
    with pytest.raises(isolation.UnsafeTestConfiguration, match="query parameter"):
        isolation.isolated_test_redis_url("redis://redis:6379/0?db=3")


def test_redis_password_is_never_echoed():
    with pytest.raises(isolation.UnsafeTestConfiguration) as excinfo:
        isolation.isolated_test_redis_url("redis://:hunter2-pw@redis:6379/15")
    assert "hunter2" not in str(excinfo.value)


def test_refuses_to_flush_a_redis_db_sharing_the_live_index_through_any_host():
    with pytest.raises(RuntimeError, match="live Celery broker"):
        isolation.assert_not_live_redis("redis://172.18.0.3:6390/0", ("redis", 6379, 0))


# --- this running session really is isolated -------------------------------


def test_app_database_engine_points_at_the_isolated_test_database(live_targets):
    assert isolation.is_test_database_name(database.engine.url.database)
    assert isolation.database_target(settings.database_url) != live_targets["database"]
    assert database.engine.url.database == make_url(settings.database_url).database


def test_celery_broker_and_redis_clients_use_the_isolated_redis_db(live_targets):
    live_index = live_targets["redis"][2]
    assert isolation.redis_target(settings.redis_url)[2] != live_index
    assert isolation.redis_target(celery_app.conf.broker_url)[2] != live_index
    assert isolation.redis_target(rate_limit.limiter._storage_uri)[2] != live_index
    assert account_lockout._client.connection_pool.connection_kwargs.get("db", 0) != live_index


# --- network guard (the session's real one) ---------------------------------


def test_dns_resolution_of_an_external_name_is_blocked(network_guard):
    with pytest.raises(isolation.RealNetworkAccessBlocked):
        socket.getaddrinfo("example.com", 443)
    assert any("example.com" in attempt for attempt in network_guard.blocked_attempts)
    network_guard.blocked_attempts.clear()


@pytest.mark.parametrize("lookup_name", ["gethostbyname", "gethostbyname_ex"])
def test_legacy_name_lookups_are_blocked(network_guard, lookup_name):
    # Looked up at call time, so it's the session's guarded version.
    with pytest.raises(isolation.RealNetworkAccessBlocked):
        getattr(socket, lookup_name)("example.com")
    assert any("example.com" in attempt for attempt in network_guard.blocked_attempts)
    network_guard.blocked_attempts.clear()


def test_connection_to_a_public_address_is_blocked(network_guard):
    with pytest.raises(isolation.RealNetworkAccessBlocked):
        socket.create_connection(("93.184.216.34", 443), timeout=1)
    assert any("93.184.216.34" in attempt for attempt in network_guard.blocked_attempts)
    network_guard.blocked_attempts.clear()


def test_connect_ex_to_a_public_address_is_blocked(network_guard):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(isolation.RealNetworkAccessBlocked):
            sock.connect_ex(("93.184.216.34", 443))
    assert any("93.184.216.34" in attempt for attempt in network_guard.blocked_attempts)
    network_guard.blocked_attempts.clear()


def test_connect_ex_to_a_loopback_listener_is_allowed(network_guard):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
            assert client_sock.connect_ex(listener.getsockname()) == 0
    assert network_guard.blocked_attempts == []


def test_dns_traffic_is_blocked_even_to_a_loopback_resolver(network_guard):
    """Docker's embedded resolver is 127.0.0.11 -- loopback, but it
    forwards to the real internet, so port 53 is refused everywhere."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        with pytest.raises(isolation.RealNetworkAccessBlocked):
            udp.sendto(b"\x00", ("127.0.0.11", 53))
    network_guard.blocked_attempts.clear()


def test_dnspython_queries_never_leave_the_process(network_guard):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.0
    with pytest.raises(Exception):
        resolver.resolve("example.com", "A")
    assert any("(DNS)" in attempt for attempt in network_guard.blocked_attempts)
    network_guard.blocked_attempts.clear()


def test_loopback_test_servers_are_still_reachable(network_guard):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=2):
            pass
    assert network_guard.blocked_attempts == []


# --- live-stack integration test is opt-in -----------------------------------


def test_live_stack_test_is_opt_in(monkeypatch):
    monkeypatch.delenv(isolation.LIVE_STACK_OPT_IN_ENV, raising=False)
    assert isolation.live_stack_tests_enabled() is False
    assert "app" not in isolation.allowed_test_hostnames("redis://redis:6379/15")

    monkeypatch.setenv(isolation.LIVE_STACK_OPT_IN_ENV, "1")
    assert isolation.live_stack_tests_enabled() is True
    assert "app" in isolation.allowed_test_hostnames("redis://redis:6379/15")
