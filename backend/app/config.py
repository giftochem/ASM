from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"

    database_url: str
    test_database_url: str | None = None

    redis_url: str = "redis://localhost:6379/0"

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    allowed_origins: str = "http://localhost:3000"

    # MVP default: a single global cap on how large an ip_range asset may be.
    # This will need to become a per-organization value before enterprise
    # clients with larger legitimate ranges are onboarded (Phase 4) — keep
    # any code that reads this behind a parameter, not a hardcoded constant,
    # so that swap is localized when it happens.
    max_ip_range_prefix_length: int = 20

    # --- Passive HTTP fetch (technology fingerprinting, security headers) ---
    # Ports our own outbound scanner requests are allowed to connect to.
    # This is NOT a port scanner and must not become one in Phase 2 — it
    # only restricts where http_client itself may open a connection to
    # fetch a page. Kept as a config surface now so a future authorized
    # port-scanner module (Phase 3+) has somewhere to plug in without a
    # schema/config change, but nothing in Phase 2 enumerates ports on a
    # target.
    allowed_scan_ports_raw: str = "80,443,8080,8443"
    max_redirects: int = 3
    max_response_size_bytes: int = 2 * 1024 * 1024
    http_connect_timeout_seconds: float = 5.0
    http_read_timeout_seconds: float = 5.0

    # --- Reporting ---
    reports_dir: str = "/app/reports"

    # --- Celery ---
    # Defaults to real async behavior everywhere, including tests, per
    # explicit instruction: eager mode is opt-in per test, not a global
    # default anything can quietly rely on.
    celery_task_always_eager: bool = False

    # --- Cookie auth (Phase 3a) ---
    # Secure is derived from `environment`, not an independent flag, so a
    # misconfigured .env can't accidentally ship non-Secure cookies to
    # production — see `cookie_secure` below. SameSite=strict is
    # appropriate here because the frontend is always served same-site
    # (via nginx/dev-server proxy, see docs/auth-cookie-model.md), so
    # cookies never need to cross origins at all.
    cookie_samesite: str = "strict"

    # --- Rate limiting ---
    # Applied via slowapi against Redis (the same instance Celery uses).
    # Fails CLOSED, never open, if Redis is unreachable — see
    # app/services/rate_limit.py.
    rate_limit_login: str = "5/minute"
    rate_limit_auth_refresh: str = "20/minute"
    # Applies uniformly to all scan creation, port_scanner requests
    # included. A separate, stricter tier specifically for port-scanner
    # requests would need slowapi to make a rate-limiting decision based
    # on the parsed request body (which module names were requested), not
    # just method/path/IP — not implemented here since I couldn't verify
    # a body-aware conditional limit is applied correctly without
    # shipping it unverified. The port scanner's real safety boundary in
    # this pass is the authorization gate + single-host-only scope +
    # narrow port allowlist, not a separate rate tier.
    rate_limit_scan_create: str = "20/minute"
    # Same tier as scan creation -- discovery runs reuse the identical
    # authorization/RBAC/rate-limit posture as scans, just for a
    # different kind of execution (Step 9.1).
    rate_limit_discovery_create: str = "20/minute"

    # --- Alerting & notifications (Step 9.12) ---
    # Disabled by default -- a deployment that hasn't configured SMTP
    # never creates an AlertNotification row at all (see
    # alert_service.queue_notifications), so nothing is ever left
    # pending indefinitely. The Alert row itself (in-app/API state) is
    # always created regardless of this flag; email is the optional
    # second channel, never a prerequisite for alerting to function.
    alert_notification_email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_address: str = "alerts@example.invalid"
    smtp_use_tls: bool = True
    smtp_timeout_seconds: float = 10.0

    # --- Reverse proxy trust (Phase 3b) ---
    # Empty by default: get_client_ip() (app/core/client_ip.py) falls back
    # to the raw TCP peer address for everyone, identical to pre-Phase-3b
    # behavior — X-Forwarded-For is trusted ONLY from peers listed here.
    # Left empty until a real reverse proxy (nginx) is actually in front
    # of the app; populating it prematurely — while the app's port is
    # still reachable directly — would let anyone spoof X-Forwarded-For
    # to dodge per-IP rate limiting and pollute audit-log IP addresses.
    trusted_proxy_ips_raw: str = ""

    # A completely-missing JWT_SECRET_KEY/DATABASE_URL already fails
    # startup via pydantic's own required-field check (no default above).
    # This closes the adjacent gap: the var can be *present but empty*
    # (e.g. a blank `JWT_SECRET_KEY=` line in .env, or an empty value
    # from a templating/CI substitution) and the bare `str` annotation
    # alone accepts that silently — verified empirically before adding
    # this, not assumed (Step 7A remediation, finding H-2 item 10).
    @field_validator("jwt_secret_key", "database_url")
    @classmethod
    def _reject_empty_required_secret(cls, value: str, info) -> str:
        if not value.strip():
            raise ValueError(f"{info.field_name} must not be empty")
        return value

    @property
    def trusted_proxy_ips(self) -> set[str]:
        return {ip.strip() for ip in self.trusted_proxy_ips_raw.split(",") if ip.strip()}

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def allowed_scan_ports(self) -> set[int]:
        return {int(p.strip()) for p in self.allowed_scan_ports_raw.split(",") if p.strip()}

    @property
    def cookie_secure(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
