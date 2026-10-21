"""HTTP redirects never take ASM outside the target's authorized scope.

Every fetch carries a RequestScope; the initial URL and every redirect hop
are checked against it before that hop is resolved or contacted. These
tests drive the real HttpDiscoveryProvider, scan modules and
http_client.fetch_url / net_safety path with two instrumented seams and
no real network:

- socket.getaddrinfo -> a fake resolver that records every lookup (IP
  literals and inet_aton spellings resolve exactly as the real one would,
  without network access);
- http_client.build_pinned_transport -> records the IP each hop's
  connection is pinned to (where production opens the TCP connection) and
  returns a MockTransport that records every request actually sent.

For every out-of-scope destination they prove: zero DNS lookups of it,
zero connections to it, zero requests to it, and nothing of it attributed.
"""

import ipaddress
import socket
import uuid
from datetime import datetime, timezone

import httpx
import pytest

from app.discovery import http_provider
from app.discovery.http_provider import HttpDiscoveryProvider
from app.models.asset import Asset
from app.models.discovery_result import DiscoveryResult
from app.models.discovery_run import DiscoveryRun
from app.models.observation import Observation
from app.models.user import User
from app.scanners import http_client
from app.scanners.headers_module import HeadersModule
from app.scanners.http_client import FetchError, FetchResult, RequestScope, ScopeRejection
from app.scanners.technology_module import TechnologyModule
from app.services import exposure_evidence_service

SEED = "seed.example"
SEED_SCOPE = RequestScope.for_target(SEED)
LOOKALIKE = "sееd.example"  # "seed.example" with two Cyrillic "е" (U+0435)
LOOKALIKE_IDNA = LOOKALIKE.encode("idna").decode()
_REAL_INET_ATON = socket.inet_aton

DNS = {
    "seed.example": ["52.0.0.10"],
    "www.seed.example": ["52.0.0.11"],
    "unrelated.example.net": ["52.0.0.20"],
    LOOKALIKE_IDNA: ["52.0.0.22"],
    "a-site.example": ["52.0.0.40"],
    "b-site.example": ["52.0.0.41"],
    # In-scope names resolving to blocked addresses: scope allows them,
    # the SSRF policy must still refuse them before any connection.
    "internal.seed.example": ["10.0.0.5"],
    "metadata.seed.example": ["169.254.169.254"],
    "cgnat.seed.example": ["100.100.100.200"],
    "reserved.seed.example": ["240.0.0.1"],
    "loopback.seed.example": ["127.0.0.1"],
    "mapped.seed.example": ["::ffff:127.0.0.1"],
}


class Net:
    def __init__(self, responses=None, dns=None):
        self.dns = dict(DNS, **(dns or {}))
        self.responses = responses or {}
        self.lookups: list[str] = []
        self.pins: list[str] = []
        self.requests: list[str] = []  # "scheme://host:port/path" as sent
        self._answers: dict[str, int] = {}

    def install(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", self._getaddrinfo)
        monkeypatch.setattr(http_client, "build_pinned_transport", self._pinned_transport)
        return self

    def _getaddrinfo(self, host, port, *args, **kwargs):
        name = host.rstrip(".").lower()
        self.lookups.append(name)
        try:
            ips = [str(ipaddress.ip_address(name))]
        except ValueError:
            try:
                ips = [socket.inet_ntoa(_REAL_INET_ATON(name))]
            except OSError:
                answer = self.dns.get(name)
                if callable(answer):
                    self._answers[name] = self._answers.get(name, 0) + 1
                    answer = answer(self._answers[name])
                if not answer:
                    raise socket.gaierror(f"test resolver: no record for {name}")
                ips = answer
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
             (ip, port, 0, 0) if ":" in ip else (ip, port))
            for ip in ips
        ]

    def _pinned_transport(self, pinned_ip, verify=True):
        self.pins.append(pinned_ip)

        def handler(request: httpx.Request) -> httpx.Response:
            url = request.url
            host = url.raw_host.decode("ascii").rstrip(".").lower()
            port = url.port or (443 if url.scheme == "https" else 80)
            sent = f"{url.scheme}://{host}:{port}{url.path}"
            self.requests.append(sent)
            spec = self.responses.get(sent)
            if spec is None:
                return httpx.Response(404, text="not configured", request=request)
            status, location = spec
            headers = {"Location": location} if location else {
                "Server": f"server-of-{host}", "X-Powered-By": "PHP/8.3", "Content-Type": "text/html",
                "Strict-Transport-Security": "max-age=63072000"}
            return httpx.Response(status, headers=headers, text=f"<title>{host}</title>", request=request)

        return httpx.MockTransport(handler)

    def assert_never_touched(self, host: str, ips=()):
        host = host.rstrip(".").lower()
        ips = list(ips) or self.dns.get(host, [])
        assert host not in self.lookups, f"{host} was resolved"
        assert not any(ip in self.pins for ip in ips), f"a connection was pinned to {host}"
        assert not any(f"://{host}:" in sent for sent in self.requests), f"{host} was requested"


# --- in-scope redirects keep working -------------------------------------------------------------


@pytest.mark.parametrize("start,location,final", [
    ("https://seed.example/", "/home", "https://seed.example:443/home"),                      # same host
    ("https://seed.example/", "https://www.seed.example/", "https://www.seed.example:443/"),  # authorized subdomain
    ("http://seed.example/", "https://seed.example/", "https://seed.example:443/"),           # http -> https
    ("https://seed.example/", "http://seed.example/plain", "http://seed.example:80/plain"),   # https -> http
    ("https://seed.example/", "https://seed.example:8443/alt", "https://seed.example:8443/alt"),  # allowlisted port
    ("https://seed.example/", "https://SEED.EXAMPLE./upper", "https://seed.example:443/upper"),   # case + trailing dot
])
def test_in_scope_redirects_are_followed(monkeypatch, start, location, final):
    first = start.replace("seed.example/", "seed.example:443/") if start.startswith("https") else start.replace("seed.example/", "seed.example:80/")
    net = Net({first: (301, location), final: (200, None)}).install(monkeypatch)

    result = http_client.fetch_url(start, scope=SEED_SCOPE)

    assert isinstance(result, FetchResult) and result.status_code == 200 and result.redirect_count == 1
    assert net.requests == [first, final]


# --- out-of-scope destinations are never contacted --------------------------------------------------


@pytest.mark.parametrize("location,rejected_host", [
    ("https://unrelated.example.net/landing", "unrelated.example.net"),
    ("http://unrelated.example.net:8080/", "unrelated.example.net"),         # an allowlisted port doesn't help
    ("https://unrelated.example.net:8443/", "unrelated.example.net"),
    ("//unrelated.example.net/protocol-relative", "unrelated.example.net"),
    ("https://seed.example@unrelated.example.net/", "unrelated.example.net"),  # userinfo trick
    ("https://seed.example\\@unrelated.example.net/", "unrelated.example.net"),  # backslash userinfo trick
    ("https://unrelated.example.net#@seed.example/", "unrelated.example.net"),   # fragment trick
    (f"https://{LOOKALIKE_IDNA}/", LOOKALIKE_IDNA),                                # IDN look-alike (punycode)
    ("https://seed.example.unrelated.example.net/", "seed.example.unrelated.example.net"),  # suffix trick
    ("https://notseed.example/", "notseed.example"),                                   # label-boundary trick
])
def test_out_of_scope_redirect_is_rejected_before_dns_connection_or_request(monkeypatch, location, rejected_host):
    net = Net({"https://seed.example:443/": (302, location)}).install(monkeypatch)

    result = http_client.fetch_url("https://seed.example/", scope=SEED_SCOPE)

    assert isinstance(result, ScopeRejection)
    assert result.host == rejected_host and result.redirect_count == 1
    assert "@" not in result.url and "#" not in result.url  # no credentials or fragment recorded
    assert net.requests == ["https://seed.example:443/"]
    assert net.lookups == ["seed.example"] and net.pins == ["52.0.0.10"]
    net.assert_never_touched(rejected_host)


def test_unicode_lookalike_target_url_is_rejected_before_resolution(monkeypatch):
    net = Net().install(monkeypatch)

    result = http_client.fetch_url(f"https://{LOOKALIKE}/", scope=SEED_SCOPE)

    assert isinstance(result, ScopeRejection) and result.host == LOOKALIKE_IDNA
    assert net.lookups == [] and net.pins == [] and net.requests == []


@pytest.mark.parametrize("chain,rejected_host", [
    # A later hop leaves scope.
    ({"https://seed.example:443/": (301, "https://www.seed.example/"),
      "https://www.seed.example:443/": (302, "https://unrelated.example.net/")}, "unrelated.example.net"),
    # Bounce chain: authorized -> unauthorized -> authorized.
    ({"https://seed.example:443/": (302, "https://unrelated.example.net/bounce"),
      "https://seed.example:443/final": (200, None)}, "unrelated.example.net"),
])
def test_multi_hop_chain_stops_at_the_first_out_of_scope_hop(monkeypatch, chain, rejected_host):
    net = Net(chain).install(monkeypatch)

    result = http_client.fetch_url("https://seed.example/", scope=SEED_SCOPE)

    assert isinstance(result, ScopeRejection) and result.host == rejected_host
    assert "https://seed.example:443/final" not in net.requests  # the bounce never completes
    net.assert_never_touched(rejected_host)


@pytest.mark.parametrize("location", [
    "http://2130706433/",       # decimal 127.0.0.1
    "http://0x7f.1/",           # hex/short 127.0.0.1
    "http://127.1/",            # short 127.0.0.1
    "http://10.0.0.5/",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.100.100.200/",  # CGNAT
    "http://[::ffff:127.0.0.1]/",
    "http://52.0.0.10/",        # even the seed's own IP: an IP literal is not a hostname's scope
    "http://localhost/",
])
def test_ip_literals_and_alternate_spellings_are_outside_a_hostname_scope(monkeypatch, location):
    net = Net({"https://seed.example:443/": (302, location)}).install(monkeypatch)

    result = http_client.fetch_url("https://seed.example/", scope=SEED_SCOPE)

    assert isinstance(result, ScopeRejection)
    assert net.lookups == ["seed.example"] and net.pins == ["52.0.0.10"] and len(net.requests) == 1


# --- scheme, port and credential rules still apply inside scope ---------------------------------------


@pytest.mark.parametrize("location,reason", [
    ("ftp://seed.example/file", "unsupported scheme"),
    ("https://seed.example:2222/x", "port 2222"),
    ("https://user:pw@seed.example/x", "credentials"),
])
def test_in_scope_destinations_still_obey_scheme_port_and_credential_rules(monkeypatch, location, reason):
    net = Net({"https://seed.example:443/": (302, location)}).install(monkeypatch)

    result = http_client.fetch_url("https://seed.example/", scope=SEED_SCOPE)

    assert isinstance(result, FetchError) and reason in result.reason
    assert net.requests == ["https://seed.example:443/"] and net.pins == ["52.0.0.10"]
    assert "pw" not in result.reason  # credentials never echoed


# --- SSRF and DNS rebinding are still enforced independently of scope ----------------------------------


@pytest.mark.parametrize("host,blocked_ip", [
    ("internal.seed.example", "10.0.0.5"),
    ("metadata.seed.example", "169.254.169.254"),
    ("cgnat.seed.example", "100.100.100.200"),
    ("reserved.seed.example", "240.0.0.1"),
    ("loopback.seed.example", "127.0.0.1"),
    ("mapped.seed.example", "::ffff:127.0.0.1"),
])
def test_in_scope_names_resolving_to_blocked_addresses_are_never_connected(monkeypatch, host, blocked_ip):
    net = Net({"https://seed.example:443/": (302, f"https://{host}/")}).install(monkeypatch)

    result = http_client.fetch_url("https://seed.example/", scope=SEED_SCOPE)

    assert isinstance(result, FetchError) and "resolves to a blocked address" in result.reason
    assert host in net.lookups  # in scope, so it is resolved -- and then refused
    assert blocked_ip not in net.pins and net.requests == ["https://seed.example:443/"]


def test_ip_target_in_a_blocked_range_is_still_refused_by_ssrf_policy(monkeypatch):
    net = Net().install(monkeypatch)

    result = http_client.fetch_url("http://10.0.0.5/", scope=RequestScope.for_target("10.0.0.5"))

    assert isinstance(result, FetchError) and "blocked" in result.reason
    assert net.pins == [] and net.requests == []


def test_dns_rebinding_between_hops_is_refused_and_connections_stay_pinned(monkeypatch):
    rebinding = {"rebind.seed.example": lambda n: ["52.0.0.30"] if n == 1 else ["127.0.0.1"]}
    net = Net({"https://seed.example:443/": (302, "https://rebind.seed.example/a"),
               "https://rebind.seed.example:443/a": (302, "https://rebind.seed.example/b")}, dns=rebinding).install(monkeypatch)

    result = http_client.fetch_url("https://seed.example/", scope=SEED_SCOPE)

    assert net.pins == ["52.0.0.10", "52.0.0.30"]  # each hop pinned to the address it validated
    assert isinstance(result, FetchError) and "resolves to a blocked address" in result.reason
    assert "127.0.0.1" not in net.pins


# --- the API fails closed ------------------------------------------------------------------------------


def test_scope_is_required_and_a_bare_scope_permits_nothing(monkeypatch):
    net = Net().install(monkeypatch)

    with pytest.raises(TypeError):
        http_client.fetch_url("https://seed.example/")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        http_client.fetch(SEED)  # type: ignore[call-arg]
    result = http_client.fetch_url("https://seed.example/", scope=RequestScope())

    assert isinstance(result, ScopeRejection)
    assert net.lookups == [] and net.pins == [] and net.requests == []


def test_scope_of_an_asset_value():
    assert RequestScope.for_target("Seed.Example.") == RequestScope(hostname="seed.example")
    assert RequestScope.for_target("https://api.seed.example/v1") == RequestScope(hostname="api.seed.example")
    assert RequestScope.for_target("52.0.0.10") == RequestScope(ip="52.0.0.10")
    assert RequestScope.for_target("2001:db8::1") == RequestScope(ip="2001:db8::1")
    with pytest.raises(ValueError):
        RequestScope.for_target("")


# --- HTTP discovery provider ----------------------------------------------------------------------------


def test_discovery_records_an_out_of_scope_redirect_without_contacting_it(monkeypatch):
    net = Net({"https://seed.example:443/": (302, "https://unrelated.example.net/landing"),
               "http://seed.example:80/": (301, "https://seed.example/"),
               }).install(monkeypatch)

    result = HttpDiscoveryProvider().discover(SEED)

    by_scheme = {o.scheme: o for o in result.http_observations}
    https = by_scheme["https"]
    assert https.left_authorized_scope is True and https.external_redirect_host == "unrelated.example.net"
    assert https.final_url == "https://unrelated.example.net/landing" and https.redirect_count == 1
    assert https.status_code is None and https.server is None and https.title is None and https.technology_evidence == []
    net.assert_never_touched("unrelated.example.net")


def test_discovery_bounce_chain_is_not_recorded_as_in_scope_evidence(monkeypatch):
    net = Net({"https://seed.example:443/": (302, "https://unrelated.example.net/bounce"),
               "https://unrelated.example.net:443/bounce": (302, "https://seed.example/final"),
               "https://seed.example:443/final": (200, None)}).install(monkeypatch)

    observation = http_provider._observe_scheme("https://seed.example/", "https", SEED)

    assert observation.left_authorized_scope is True and observation.status_code is None
    net.assert_never_touched("unrelated.example.net")


# --- security headers and technology scan modules -------------------------------------------------------


@pytest.mark.parametrize("module_cls", [HeadersModule, TechnologyModule])
def test_scan_modules_never_follow_or_attribute_an_out_of_scope_redirect(monkeypatch, module_cls):
    net = Net({"https://seed.example:443/": (302, "https://unrelated.example.net/"),
               "http://seed.example:80/": (302, "https://unrelated.example.net/")}).install(monkeypatch)

    result = module_cls().run(SEED)

    assert result.findings == [] and result.raw_data == {}
    assert result.error and "outside the target's authorized scope" in result.error and "unrelated.example.net" in result.error
    net.assert_never_touched("unrelated.example.net")


@pytest.mark.parametrize("module_cls", [HeadersModule, TechnologyModule])
def test_scan_modules_still_analyze_in_scope_redirects(monkeypatch, module_cls):
    net = Net({"https://seed.example:443/": (301, "https://www.seed.example/"),
               "https://www.seed.example:443/": (200, None)}).install(monkeypatch)

    result = module_cls().run(SEED)

    assert result.error is None and result.findings
    assert result.raw_data["final_url"] == "https://www.seed.example/"
    assert net.requests == ["https://seed.example:443/", "https://www.seed.example:443/"]


@pytest.mark.parametrize("location,followed", [
    ("https://52.0.0.10/home", True),        # same address
    ("https://seed.example/", False),        # a hostname, even one resolving elsewhere
    ("http://52.0.0.11/", False),            # a different address
    ("http://0x34.0.0.10/", False),          # an alternate spelling of the same address
    ("http://[::ffff:52.0.0.10]/", False),   # the same address, IPv4-mapped
])
def test_ip_address_scan_targets_only_follow_redirects_to_the_same_address(monkeypatch, location, followed):
    net = Net({"https://52.0.0.10:443/": (302, location), "https://52.0.0.10:443/home": (200, None),
               "http://52.0.0.10:80/": (302, location)}).install(monkeypatch)

    result = HeadersModule().run("52.0.0.10")

    if followed:
        assert result.error is None and result.raw_data["final_url"] == "https://52.0.0.10/home"
    else:
        assert result.error and "outside the target's authorized scope" in result.error and result.findings == []
        assert "seed.example" not in net.lookups and "52.0.0.11" not in net.pins
        assert all(sent.startswith(("https://52.0.0.10:", "http://52.0.0.10:")) for sent in net.requests)


# --- end to end: organization isolation and no false exposure confirmation ------------------------------------


def _org_asset(client, register_user, db, *, label, value):
    email = f"redirect-scope-{label}-{uuid.uuid4().hex[:6]}@example.com"
    headers = register_user(org_name=f"Redirect Scope {label}", email=email)
    created = client.post("/assets", json={"asset_type": "domain", "value": value}, headers=headers)
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]
    confirmed = client.post(f"/assets/{asset_id}/confirm-authorization",
                            json={"authorization_confirmed": True, "attestation_note": "test fixture"}, headers=headers)
    assert confirmed.status_code == 200, confirmed.text
    user = db.query(User).filter(User.email == email).one()
    return headers, user.organization_id, uuid.UUID(asset_id)


def test_discovery_never_contacts_or_attributes_another_organizations_host(client, register_user, db, monkeypatch):
    a_headers, a_org, a_asset = _org_asset(client, register_user, db, label="A", value="a-site.example")
    b_headers, b_org, b_asset = _org_asset(client, register_user, db, label="B", value="b-site.example")
    net = Net({"https://a-site.example:443/": (302, "https://b-site.example/"),
               "http://a-site.example:80/": (302, "https://unrelated.example.net/bounce"),
               "https://unrelated.example.net:443/bounce": (302, "https://a-site.example/final"),
               "https://a-site.example:443/final": (200, None),
               "https://b-site.example:443/": (200, None)}).install(monkeypatch)
    marked = client.patch(f"/assets/{a_asset}", json={"criticality": "high"}, headers=a_headers)
    assert marked.status_code == 200, marked.text
    b_observations_before = db.query(Observation).filter(Observation.asset_id == b_asset).count()

    run = client.post("/discovery/runs", json={"seed_asset_id": str(a_asset), "provider_name": "http"}, headers=a_headers)

    assert run.status_code == 201, run.text
    assert run.json()["status"] == "completed"
    net.assert_never_touched("b-site.example")
    net.assert_never_touched("unrelated.example.net")
    results = db.query(DiscoveryResult).filter(DiscoveryResult.discovery_run_id == uuid.UUID(run.json()["id"])).all()
    assert sorted(r.outcome.value for r in results) == ["rejected", "rejected"]
    assert sorted(r.evidence["external_redirect_host"] for r in results) == ["b-site.example", "unrelated.example.net"]
    assert all(r.resulting_asset_id == a_asset for r in results)

    # Nothing attributed or created in either organization.
    assert {a.value for a in db.query(Asset).filter(Asset.organization_id == a_org)} == {"a-site.example"}
    assert {a.value for a in db.query(Asset).filter(Asset.organization_id == b_org)} == {"b-site.example"}
    assert db.query(DiscoveryRun).filter(DiscoveryRun.organization_id == b_org).count() == 0
    assert db.query(Observation).filter(Observation.asset_id == b_asset).count() == b_observations_before

    # No false exposure confirmation from rejected redirects (bounce included).
    exposure = exposure_evidence_service.assess_asset_exposure(db, a_org, a_asset, as_of=datetime.now(timezone.utc))
    assert exposure.is_observed_entry_point is False
    paths = client.get("/assets/exposure-paths", headers=a_headers).json()
    assert paths["eligible_target_count"] == 1 and paths["entry_point_count"] == 0 and paths["path_count"] == 0
    assert client.get("/assets/exposure-paths", headers=b_headers).json()["eligible_target_count"] == 0
