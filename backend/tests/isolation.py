"""Fail-closed safety rails for the pytest suite.

The suite's fixtures are destructive by design: every test TRUNCATEs
every table, the session DROPs them all at the end, and every test
FLUSHes its Redis DB. This module guarantees those operations can only
land on resources that exist purely for tests, and that ordinary test
runs never reach the real network:

- validated_test_database_url: ENVIRONMENT must be an allowlisted
  non-production value; TEST_DATABASE_URL must be set (no fallback to
  DATABASE_URL), must name a database following the strict
  `<name>_test` convention, and must not name the same database as
  DATABASE_URL -- compared by name alone, since hostnames can alias the
  same server.
- verify_test_database_marker: independently of every name/URL rule,
  the database TEST_DATABASE_URL actually reaches must carry the explicit
  marker provisioning puts on a disposable test database.
- isolated_test_redis_url: tests get their own Redis DB index (15 unless
  TEST_REDIS_URL says otherwise) that must differ from the live index
  regardless of host, never the DB the live Celery broker and rate
  limiter use.
- NetworkGuard: blocks DNS resolution of non-allowlisted hostnames, any
  connection/datagram to a non-loopback address that isn't an
  allowlisted test service, and anything addressed to port 53.

Imports nothing from `app` except app.config's dependency-free
environment allowlist, so tests/conftest.py can apply these checks
before any other app module is imported. Error messages never include
credentials -- only database names, hosts, ports and DB indexes.
"""

import ipaddress
import os
import re
import socket
from urllib.parse import parse_qs, urlparse

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from app.config import TEST_TOOLING_ENVIRONMENTS, is_test_tooling_environment

TEST_REDIS_DB_INDEX = 15
LIVE_STACK_OPT_IN_ENV = "ASM_RUN_LIVE_STACK_TESTS"
_DEFAULT_LIVE_STACK_BASE_URL = "http://app:8000"

# The explicit marker that makes a database "a disposable test database":
# a database comment set at provisioning time (docker/postgres/
# init-test-db.sql does it on fresh volumes), never by the suite itself.
TEST_DATABASE_MARKER = "asm-disposable-test-database"
_TEST_DATABASE_NAME = re.compile(r"[a-z0-9_]+_test")


class UnsafeTestConfiguration(Exception):
    """The configured test resources could overlap real data -- the suite must not start."""


def database_target(url: str) -> tuple[str, int, str]:
    """(host, port, database) -- enough to compare two URLs without ever
    touching their credentials."""
    try:
        parsed = make_url(url)
    except Exception:
        # Never chain the parser's error: it would echo the raw URL,
        # credentials included.
        raise UnsafeTestConfiguration("a database URL could not be parsed") from None
    return ((parsed.host or "").lower(), parsed.port or 5432, parsed.database or "")


def is_test_database_name(name: str | None) -> bool:
    """Strict: lowercase letters, digits and underscores, ending in
    `_test` (e.g. asm_test). A substring match would also accept names
    like asm_latest or contest."""
    return bool(name) and _TEST_DATABASE_NAME.fullmatch(name) is not None


def validated_test_database_url(
    test_database_url: str | None, database_url: str | None, environment: str | None
) -> str:
    if not is_test_tooling_environment(environment):
        raise UnsafeTestConfiguration(
            f"ENVIRONMENT is {environment!r}; the test suite only runs with one of {sorted(TEST_TOOLING_ENVIRONMENTS)}"
        )
    if not test_database_url:
        raise UnsafeTestConfiguration(
            "TEST_DATABASE_URL is not set. The suite truncates and drops every table it touches, so it requires "
            "an explicitly configured, isolated test database (e.g. .../asm_test) and never falls back to DATABASE_URL"
        )
    _, _, test_name = database_target(test_database_url)
    if not is_test_database_name(test_name):
        raise UnsafeTestConfiguration(
            f"TEST_DATABASE_URL names database {test_name!r}; it must be a dedicated test database named "
            "'<name>_test' (lowercase letters, digits and underscores)"
        )
    if database_url and database_target(database_url)[2] == test_name:
        # Compared by name alone, deliberately: a Postgres database is
        # (server, name), and two different hostnames/IPs/ports can reach
        # the same server -- so a shared name is refused whatever the hosts.
        raise UnsafeTestConfiguration(
            f"TEST_DATABASE_URL and DATABASE_URL both name database {test_name!r}; they could be the same "
            "database reached through different hostnames, so the suite refuses"
        )
    return test_database_url


def verify_test_database_marker(test_database_url: str, expected_marker: str = TEST_DATABASE_MARKER) -> None:
    """Connects to the test database only -- one read-only query -- and
    requires the explicit marker comment provisioning puts on a disposable
    test database. Independent of every name/URL rule above: whatever
    hostname or alias TEST_DATABASE_URL uses, this checks the database it
    actually reaches. Anything that prevents verification refuses."""
    try:
        engine = create_engine(test_database_url, poolclass=NullPool)
        try:
            with engine.connect() as conn:
                marker = conn.execute(
                    text(
                        "SELECT pg_catalog.shobj_description(oid, 'pg_database') "
                        "FROM pg_catalog.pg_database WHERE datname = current_database()"
                    )
                ).scalar()
        finally:
            engine.dispose()
    except Exception as exc:
        # Class name only: driver errors can echo connection details.
        raise UnsafeTestConfiguration(
            f"could not verify that TEST_DATABASE_URL reaches a marked test database ({type(exc).__name__})"
        ) from None
    if marker != expected_marker:
        raise UnsafeTestConfiguration(
            "the database TEST_DATABASE_URL reaches is not marked as a disposable test database. Mark a "
            f"dedicated test database once with: COMMENT ON DATABASE <name> IS '{expected_marker}' "
            "(fresh volumes are marked by docker/postgres/init-test-db.sql)"
        )


def assert_is_test_database(url) -> None:
    """Re-checked immediately before every DROP/TRUNCATE, independent of
    the startup validation -- defense in depth against the engine ever
    being rebound to something else."""
    if not is_test_database_name(url.database):
        raise RuntimeError(f"refusing a destructive operation on non-test database {url.database!r}")


def redis_target(url: str) -> tuple[str, int, int]:
    """(host, port, db index) of a redis:// or rediss:// URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ("redis", "rediss"):
        raise UnsafeTestConfiguration(f"unsupported Redis URL scheme {parsed.scheme!r} (expected redis:// or rediss://)")
    if "db" in parse_qs(parsed.query):
        # redis-py lets a ?db= query override the path; refusing it keeps
        # "which DB is this" unambiguous.
        raise UnsafeTestConfiguration("a Redis URL selects its DB via a ?db= query parameter; use the /<index> path form")
    path = (parsed.path or "").strip("/")
    try:
        db_index = int(path) if path else 0
    except ValueError:
        raise UnsafeTestConfiguration("a Redis URL has a non-numeric DB index") from None
    return ((parsed.hostname or "").lower(), parsed.port or 6379, db_index)


def isolated_test_redis_url(redis_url: str, test_redis_url: str | None = None) -> str:
    """The test DB index must differ from the live one REGARDLESS of host:
    hostnames, IPs, ports and forwards can all alias the same server, but a
    different DB index is a different logical database even on the same
    server -- so no host comparison is trusted here."""
    live_index = redis_target(redis_url)[2]
    candidate = test_redis_url or urlparse(redis_url)._replace(path=f"/{TEST_REDIS_DB_INDEX}").geturl()
    candidate_index = redis_target(candidate)[2]
    if candidate_index == live_index:
        raise UnsafeTestConfiguration(
            f"the test Redis DB index ({candidate_index}) is the same index REDIS_URL uses for the live Celery "
            "broker and rate limiter; hostnames can alias the same server, so a different index is required "
            "whatever the host -- set TEST_REDIS_URL to one"
        )
    return candidate


def assert_not_live_redis(redis_url: str, live_target: tuple[str, int, int]) -> None:
    if redis_target(redis_url)[2] == live_target[2]:
        raise RuntimeError("refusing to flush a Redis DB with the live Celery broker / rate limiter's DB index")


def live_stack_tests_enabled() -> bool:
    return os.environ.get(LIVE_STACK_OPT_IN_ENV, "").strip().lower() in ("1", "true", "yes")


def live_stack_base_url() -> str:
    return os.environ.get("ASM_INTEGRATION_BASE_URL", _DEFAULT_LIVE_STACK_BASE_URL)


def allowed_test_hostnames(test_redis_url: str) -> set[str]:
    """Hostnames tests may legitimately resolve and connect to: the test
    Redis server, this machine's own hostname (answered locally from
    /etc/hosts -- e.g. smtplib looks it up for its EHLO name even when
    talking to a loopback test server), plus the running app only when the
    live-stack test has been explicitly opted into. Postgres isn't listed
    because libpq connects from C, outside Python's socket layer."""
    hostnames = {"localhost", socket.gethostname().lower(), redis_target(test_redis_url)[0]}
    if live_stack_tests_enabled():
        hostnames.add((urlparse(live_stack_base_url()).hostname or "").lower())
    return {name for name in hostnames if name}


class RealNetworkAccessBlocked(OSError):
    """Raised in place of real network I/O during tests."""


def _normalize_host(host) -> str:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    return str(host).split("%", 1)[0].strip().rstrip(".").lower()


def _ip_or_none(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


class NetworkGuard:
    """Patches the Python-level DNS/connect/sendto entry points for the
    whole test session. Loopback (local test servers) and allowlisted
    test services pass through; everything else is recorded and refused
    with RealNetworkAccessBlocked. conftest fails any test that triggered
    a block, even if the code under test swallowed the exception.

    Port 53 is refused even on loopback: inside Docker the system resolver
    is 127.0.0.11, which forwards to the real internet, so "loopback"
    alone is not safe for DNS.

    A test that monkeypatches socket.getaddrinfo itself replaces the guard
    for that test only -- correct, since that test supplies its own fake
    answers; monkeypatch restores the guard afterwards.
    """

    def __init__(self, allowed_hostnames: set[str]) -> None:
        self.allowed_hostnames = {_normalize_host(name) for name in allowed_hostnames if name}
        self.allowed_ips: set[str] = set()
        self.blocked_attempts: list[str] = []

    def install(self, monkeypatch) -> None:
        real_getaddrinfo = socket.getaddrinfo
        for hostname in self.allowed_hostnames:
            try:
                for *_unused, sockaddr in real_getaddrinfo(hostname, None):
                    self.allowed_ips.add(_normalize_host(sockaddr[0]))
            except OSError:
                pass  # e.g. a Docker-only hostname when running outside Docker: nothing extra is allowed

        real_gethostbyname = socket.gethostbyname
        real_gethostbyname_ex = socket.gethostbyname_ex
        real_connect = socket.socket.connect
        real_connect_ex = socket.socket.connect_ex
        real_sendto = socket.socket.sendto
        guard = self

        def guarded_getaddrinfo(*args, **kwargs):
            guard.check_hostname(args[0] if args else kwargs.get("host"), "DNS resolution")
            return real_getaddrinfo(*args, **kwargs)

        def guarded_gethostbyname(hostname):
            guard.check_hostname(hostname, "DNS resolution")
            return real_gethostbyname(hostname)

        def guarded_gethostbyname_ex(hostname):
            guard.check_hostname(hostname, "DNS resolution")
            return real_gethostbyname_ex(hostname)

        def guarded_connect(sock, address):
            guard.check_destination(address, "connection")
            return real_connect(sock, address)

        def guarded_connect_ex(sock, address):
            guard.check_destination(address, "connection")
            return real_connect_ex(sock, address)

        def guarded_sendto(sock, data, *args):
            guard.check_destination(args[-1] if args else None, "datagram")
            return real_sendto(sock, data, *args)

        monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
        monkeypatch.setattr(socket, "gethostbyname", guarded_gethostbyname)
        monkeypatch.setattr(socket, "gethostbyname_ex", guarded_gethostbyname_ex)
        monkeypatch.setattr(socket.socket, "connect", guarded_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
        monkeypatch.setattr(socket.socket, "sendto", guarded_sendto)

    def _block(self, description: str) -> None:
        self.blocked_attempts.append(description)
        raise RealNetworkAccessBlocked(
            f"real network access blocked during tests: {description} -- mock the network boundary instead"
        )

    def check_hostname(self, host, kind: str) -> None:
        if host is None:
            return
        name = _normalize_host(host)
        if name in ("", "localhost") or name in self.allowed_hostnames or _ip_or_none(name) is not None:
            return  # numeric hosts never trigger a DNS query
        self._block(f"{kind} of {host!r}")

    def check_destination(self, address, kind: str) -> None:
        if not isinstance(address, tuple) or len(address) < 2:
            return  # an AF_UNIX path, not network I/O
        host, port = address[0], address[1]
        if port == 53:
            self._block(f"{kind} to {host}:{port} (DNS)")
        name = _normalize_host(host)
        ip = _ip_or_none(name)
        if ip is None:
            # A hostname handed straight to connect() is resolved in C,
            # bypassing guarded_getaddrinfo -- so it's checked by name here.
            if name == "localhost" or name in self.allowed_hostnames:
                return
            self._block(f"{kind} to {host}:{port}")
            return
        mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        if ip.is_loopback or (mapped is not None and mapped.is_loopback) or name in self.allowed_ips:
            return
        self._block(f"{kind} to {host}:{port}")
