# Attack Surface Mapper (ASM)

A platform that discovers, inventories, analyzes, and reports on an
organization's externally visible assets.

## ⚠️ Authorization & scope disclaimer

**This is a defensive security tool for authorized use only.** You may only
scan assets that you own, or for which you hold explicit written permission
to test (e.g. a signed penetration-testing engagement or MSSP contract).

Scanning systems without authorization may violate the Computer Fraud and
Abuse Act (US), the Computer Misuse Act (UK), or equivalent computer-crime
laws in other jurisdictions — regardless of intent.

**Enforcement**: every `Asset` has an `authorization_confirmed` flag that
defaults to `false`. No scanner module — passive or active — will run
against an asset until a user with the `admin` or `analyst` role has
explicitly confirmed authorization via
`POST /assets/{id}/confirm-authorization`. That confirmation can be
withdrawn at any time via `POST /assets/{id}/revoke-authorization`.

This is a **two-layer** guardrail, not just a create-time check:
1. `app/services/scan_service.validate_scan_request()` checks it
   synchronously when a scan is requested (immediate 403 if unconfirmed).
2. `app/services/scan_executor.execute_scan()` checks it **again**,
   fail-closed, immediately before any scanner module actually runs —
   because a scan can sit queued for a real, possibly non-trivial amount
   of time before a worker picks it up, and authorization can be revoked,
   the asset deactivated, or the scan cancelled in that window. If any of
   that happened, the scan is marked `failed` (or stays `cancelled`) and
   nothing runs, no matter what its state was when it was queued.

Neither check can be bypassed through the API. The confirming/revoking
user and timestamp are recorded on the asset and in the audit log.

## Status: foundation complete, pending release-readiness signoff

Backend, frontend, authentication/credential-security remediation, and
production deployment posture (nginx/TLS, hardened Docker Compose) are
all built and tested. A release-readiness audit (Step 7C) has run once
against a genuinely fresh clone and returned **PASS WITH FINDINGS**; this
README update is part of closing those findings out before the
`v0.1.0-security-foundation` tag. See "Release readiness (Step 7C)"
below for what that audit actually checks and its current state.

Once tagged, subsequent work (Step 8 onward — Asset Intelligence,
Passive/Active Discovery, Risk Engine, Continuous Monitoring, etc.) is
scoped against a single product-capability statement, not a feature
count:

> Given an authorized organization, ASM can discover its externally
> visible attack surface, continuously determine what changed, identify
> security exposures, correlate them to assets and technologies,
> prioritize the risk, provide evidence and remediation guidance, notify
> the right people, and prove what happened over time.

### What's built

**Backend core (Phase 1-2)** — organization-scoped RBAC (`admin` /
`analyst` / `viewer`), WHOIS/DNS/SSL passive modules, technology
fingerprinting, security-headers analysis, the SSRF-hardened HTTP client
(closed DNS-rebinding/TOCTOU, verified TLS-hostname enforcement under IP
pinning — see "SSRF hardening" below), risk engine v1, JSON/CSV/PDF
reporting, async scan execution via Celery + Redis, audit logging on
every write action.

**Backend hardening (Phase 3a)** — cookie-based authentication
(`httpOnly`/`Secure`(prod)/`SameSite=Strict`, double-submit CSRF,
single-use rotated refresh tokens with reuse detection), `GET
/audit-logs` and `PATCH /users/{id}` (both admin-only, org-scoped),
fail-closed rate limiting (`slowapi` + Redis) on auth and scan-creation
endpoints, the port scanner module (the one active-scanning module —
TCP connect-scan only, `ip_address` assets only, allowlisted ports, must
be named explicitly), race-safe scan cancellation via atomic conditional
`UPDATE`s, and a dedicated IDOR/privilege-escalation regression suite
(`tests/test_idor_and_privilege_escalation.py`) proving cross-org
isolation and role enforcement on every endpoint, not just happy-path
RBAC.

**Frontend (Phase 3b, productized in Step 9.13)** — a React + TypeScript
+ Vite SPA (`frontend/`), styled with Tailwind, data-fetched via
TanStack Query, graph visualization via `d3-force` (Step 9.13, the
project's one chart/graph dependency). Every authenticated page renders
inside a persistent `AppShell` nav (Step 9.13). Pages: Overview, Attack
Surface (Explorer) / Asset Detail (+priority/graph/relationships/
changes), Change Timeline, Alerts, Prioritized Assets, Continuous
Monitoring, Scans / Scan Detail, Findings, Reports, Settings, Login /
Register, plus `RequireAuth`/`RequireRole` route guards and a global
`ErrorBoundary`. Talks to the backend exclusively via cookie auth (no
tokens ever touch `localStorage` or JS-readable state) — see
`docs/auth-cookie-model.md`. 47 test files / 285 tests
(`@testing-library/react` + MSW for API mocking), typechecked with
`tsc --noEmit`, built with `vite build`.

**Auth / credential-security remediation (Step 7A)** — driven by a
dedicated read-only security audit that found one Critical issue (a
git-tracked `.env.example` that had, in fact, never been rotated from
its placeholder values) plus several High/Medium findings. Fixed:
rotated all secrets and purged the tainted blob from git history;
timing-safe login (a dummy bcrypt hash is always compared against, even
for a nonexistent user, so response time can't distinguish the two);
Redis-backed account lockout (temporary, escalating-but-capped,
resets on successful login, fails closed if Redis is unreachable, real
and nonexistent emails treated identically); an atomic conditional
`UPDATE` closing a TOCTOU race in refresh-token rotation; Docker
hardened so Postgres/Redis are never host-exposed; an empty (not just
missing) `JWT_SECRET_KEY`/`DATABASE_URL` is now rejected at startup
rather than silently accepted.

**Production infrastructure (Step 7B)** — `docker-compose.prod.yml`:
`app`/`worker` run the built image only (no `--reload`, no source
bind-mount, no host port), and `nginx` terminates TLS (self-signed
placeholder until a real domain exists), redirects HTTP→HTTPS, proxies
known API route prefixes to `app`, and serves the built frontend as a
static SPA otherwise. `nginx` sits at a pinned network address so `app`
can trust its `X-Forwarded-For` deterministically for rate limiting and
audit logging. Full setup/run instructions: `docs/deployment.md`.

**Asset Intelligence (Step 8)** — the data-model foundation the product
vision's Web2+Web3 correlation and change-detection work builds on, none
of it implemented yet:
- `Asset` gained `status` (a `first_seen → active → stale → disappeared`
  lifecycle, orthogonal to the existing `is_active` admin kill-switch),
  `source`, `confidence`, `environment`, `criticality`, `owner`, `tags`,
  `first_seen`/`last_seen` — all exposed via `GET /assets`.
- Two new deduped, current-state child tables alongside the existing
  per-scan evidence tables (`DNSRecord`/`SSLInfo`/`Technology`/
  `PortScanResult`, all still historical/append-only): `Service`
  (host+port+protocol+product, the gap `PortScanResult` didn't cover)
  and `Certificate`. No API routes for these two yet.
- **The Asset Graph**: `AssetRelationship` — a plain Postgres
  adjacency-list edge between two assets (`owns`/`resolves_to`/`hosts`/
  `exposes`/`uses`/`belongs_to`/`interacts_with`/`deployed_on`/
  `served_by`/`related_to`), deliberately not a graph database — traversed
  via recursive CTEs, sufficient at ASM's per-organization scale.
  `POST /assets/{id}/relationships`, `GET /assets/{id}/relationships`
  (both directions), `POST .../relationships/{id}/mark-disappeared`
  (soft-remove — preserves history, never a hard delete).
- **Observations**: `Observation` — an immutable, append-only event log
  (`GET /assets/{id}/observations`) proving what ASM believed and when,
  rather than only ever showing current state. Written today on asset
  creation and relationship create/remove; genuine field-level diffing
  (IP changed, port opened, ...) needs real discovery/re-scanning logic
  (Step 9+) to have anything to diff.
- `AssetType` grew from 5 to 17 values toward the fuller Web2 vocabulary
  (`asn`, `http_endpoint`, `api`, `cloud_resource`, `repository` are
  creatable now); `service`/`tls_certificate`/`web3_*`/`rpc_endpoint`
  are reserved placeholders only — see "Known, disclosed debt" below.

**Discovery Intelligence (Step 9.1)** — the foundation future discovery
providers plug into. No real provider ships yet; one deterministic stub
proves the architecture end to end. **Web3 discovery is not implemented.**

- **Provider abstraction** (`app/discovery/`) mirrors the scanner-module
  pattern exactly: a `DiscoveryProvider` ABC + a static registry
  (`app/discovery/registry.py`). A provider takes an already-validated,
  already-authorized seed value and returns `DiscoveryCandidate`s (never
  raising — expected failures report via `result.error`, the same
  contract `ScanModuleResult` already uses). `StubDiscoveryProvider`
  (`app/discovery/stub_provider.py`) is the one registered provider: zero
  network I/O, deterministically reports one `www.` subdomain candidate
  for a domain/subdomain seed. **It is now test-only**: because its
  candidate has no real evidence behind it, it is absent from the
  provider catalog and rejected by every run/schedule path unless
  `ENABLE_TEST_DISCOVERY_PROVIDERS` is explicitly on, and never available
  with `ENVIRONMENT=production`; an existing stub schedule is disabled
  with an explicit reason the next time it comes due, its history kept.
  The test suite enables it for itself. Future providers (DNS, subdomain
  enumeration, certificate-transparency, HTTP, ASN/cloud/repository
  enrichment, and eventually Web3) register the same way, without
  touching the orchestration layer.
- **`DiscoveryRun`/`DiscoveryResult`** (new tables) — a run records who
  initiated discovery, org, seed asset, provider, status
  (`queued → running → completed/failed/cancelled`, its own enum, kept
  separate from `ScanStatus` the same way `FindingSeverity`/
  `RiskSeverityBand` are — passive discovery and active scanning stay
  conceptually distinct even where the shape is identical), timestamps,
  errors. A result records exactly what a provider reported, *before*
  normalization — including rejected candidates — the same "raw
  evidence vs. narrative outcome" split `Finding` already provides for
  scans.
- **Authorization**: reuses the *existing* `authorization_confirmed`
  gate and `AuthorizationNotConfirmedError` verbatim — no parallel
  authorization concept. A discovery run against an unauthorized seed
  403s exactly like a scan would.
- **Normalization layer** (`app/services/discovery_normalization_service.py`)
  turns a candidate into real rows by calling the *existing* Step 8
  services (`asset_relationship_service`, `observation_service`), not
  reimplementing them — and runs every candidate value through the
  *same* `app.core.validation.normalize_asset_value` manual asset
  creation uses, so a candidate carrying a private/loopback/reserved
  value is rejected before it ever reaches the database. This is
  discovery's SSRF/scope-expansion boundary: no new validation surface,
  it inherits the existing one. A candidate's organization is always the
  seed's — `DiscoveryCandidate` has no organization field a provider
  could even attempt to override.
- **Incremental by construction**: re-discovering an already-known asset
  refreshes `last_seen`/`confidence` (and revives it from `stale`/
  `disappeared` back to `active`) rather than creating a duplicate —
  proven under genuine concurrency (two threads racing to create the
  same asset via a Postgres `SAVEPOINT`, not just sequentially).
- **API**: `POST /discovery/runs`, `GET /discovery/runs`,
  `GET /discovery/runs/{id}`, `GET /discovery/runs/{id}/results` — same
  RBAC (`admin`/`analyst` to create), org-isolation, and rate-limiting
  (`rate_limit_discovery_create`) conventions as every other router.
  Runs synchronously in this pass (the stub does no I/O); a real,
  slow provider gets a small, additive Celery wrapper later, mirroring
  `scan_tasks.py` — not built speculatively now.

**DNS Intelligence Provider (Step 9.2)** — the first real discovery
provider, selected the same way the stub is: `POST /discovery/runs`
with `"provider_name": "dns"`. **Passive only — no brute-force
subdomain enumeration, no zone transfers, no wordlists.** Resolves
exactly the seed's own A/AAAA/CNAME/MX/NS/TXT records (6 bounded,
sequential queries against one name — `app/discovery/dns_provider.py`,
reusing `dnspython`, already a dependency via the existing
`app/scanners/dns_module.py`, no new dependency added), never queries a
name it discovers.

- **What becomes what**: A/AAAA → `ip_address` asset, `resolves_to`
  relationship. An in-scope CNAME target → `subdomain` asset,
  `resolves_to`. An in-scope MX target → `subdomain` asset, `uses`. An
  in-scope NS target → `subdomain` asset, `served_by`. All three
  relationship types already existed — no new ones were needed. TXT
  records, and any CNAME/MX/NS target **outside** the authorized scope
  (e.g. a third-party mail/CDN/DNS provider), never become an Asset —
  only an `Observation` on the seed (`change_type=dns_records_observed`,
  raw evidence JSON-serialized into the observation's value).
- **Scope enforcement**: `app.core.validation.is_hostname_in_scope`
  does a proper DNS label-boundary check, not a string suffix match —
  `example.com.evil.com` string-*ends with* `example.com` but is
  correctly rejected as a subdomain of `evil.com`, not `example.com`.
  Verified live against a real domain's real (Cloudflare) nameservers,
  correctly recorded as out-of-scope evidence, never created as assets.
- **Bounded/safety**: fixed 5s resolver timeout (matching
  `dns_module.py`'s existing constant), no custom resolver endpoint is
  ever accepted from a caller (nothing in the API surface allows one),
  and a per-record-type try/except (the same
  `NXDOMAIN`/`NoAnswer`/`NoNameservers`/`Timeout` set `dns_module.py`
  already catches, plus a broad fallback for a malformed response)
  means one failing record type can't aborts the other five or the run.
- Extended Step 9.1 minimally to support this: `DiscoveryProviderResult`
  gained an optional `seed_evidence` field (existing providers
  unaffected), and `DiscoveryResultOutcome`/`ChangeType` each gained one
  additive enum value (`observed` / `dns_records_observed`) for exactly
  this "evidence about the seed, not a new asset" case.

**Certificate Intelligence Provider (Step 9.3)** — `POST
/discovery/runs` with `"provider_name": "certificate"`. Retrieves the
TLS certificate an authorized domain/subdomain seed presents on port
443 — exactly **one** connection per run, to the seed itself — and
records its identity (subject, issuer, serial, SHA-256 fingerprint,
validity window, signature algorithm, protocol/cipher, X.509 version,
public-key algorithm/size) plus a classified SAN list. Uses the
`cryptography` library, already a dependency via the existing
`app/scanners/ssl_module.py`; the raw socket that module uses is closed
here via `net_safety.resolve_and_validate` (`app/scanners/net_safety.py`
— its own docstring already earmarked itself for exactly this: "a
hardened version of ssl_module") — the connection is pinned to a
validated IP while the real hostname is still sent as SNI, mirroring
`pinned_transport.py`'s identical approach for HTTP.

**A certificate's SAN list is evidence, never authorization** — the
central safety property of this provider:
- **In-scope** SAN hostnames (excluding the seed's own name and
  wildcard entries, which aren't connectable) become ordinary
  `subdomain` candidates via the *unmodified* Step 9.1
  `normalize_candidate` — `related_to` relationship (a shared
  certificate doesn't mean one name resolves to, hosts, or is served by
  the other; no new relationship type was needed), confidence `0.7`
  (claimed by a certificate, lower than DNS's `1.0` confirmed-by-
  resolution). Discovery-created assets always start at
  `status=first_seen` and `authorization_confirmed=false` — so a
  SAN-derived asset genuinely cannot be scanned until a human
  separately, explicitly authorizes it. Verified directly: attempting
  `POST /scans` against a freshly SAN-discovered asset still 403s.
- **External** SANs (outside the seed's authorized boundary, checked via
  the same `is_hostname_in_scope` label-boundary function Step 9.2
  built) become evidence only — folded into the certificate's own
  `Observation` — never a candidate, **never contacted**. Proven by a
  dedicated test that tracks every `socket.create_connection` call
  during a run against a certificate naming 3 external hosts: exactly
  one connection, to the seed's own address.
- Certificate/`AssetType.tls_certificate` reconciliation (open since
  Step 8.1) is now resolved, not just deferred: `Certificate` stays a
  child-detail table, never an `AssetRelationship` endpoint — nothing a
  real provider needs requires it to be a graph node. Dedup identity
  stays `(asset_id, hostname, port)` (Step 8.1's existing constraint);
  `fingerprint_sha256` decides *what kind* of `Observation` gets
  written: first time at a slot → `certificate_observed`; fingerprint
  changed (rotation) → `certificate_changed` (old/new fingerprint
  recorded, prior observations never deleted — verified with a live
  rotation test); same fingerprint re-confirmed → `unchanged`, no new
  Observation (nothing happened, so nothing is logged — the one
  outcome value hinted at back in Step 9.1 and never added until now).

**Subdomain / Host Discovery Provider (Step 9.4)** — `POST
/discovery/runs` with `"provider_name": "subdomain"`. Passive hostname
discovery via public Certificate Transparency logs
([crt.sh](https://crt.sh)): discovers hostnames that have ever had a
certificate logged naming them under an authorized domain/subdomain
seed. **Discovery evidence does not imply current reachability** — a CT
log entry means a certificate naming this hostname was issued at some
point, never that the host is live today. Confidence (`0.6`) is set
lower than any other provider in this system: DNS resolution (`1.0`)
confirms a name resolves right now; even a certificate SAN this system
retrieves live (`0.7`, Step 9.3) came from a cert just verified to still
exist. A historical CT entry confirms neither — the confidence value
says so honestly.

- **Bounded, not brute force**: exactly one outbound request per run (to
  `crt.sh`, a fixed trusted host — not the seed's own infrastructure, so
  this deliberately does *not* route through `net_safety`, unlike the
  DNS/certificate providers; the seed is only a query parameter here,
  never a connection target). No wordlists, no guessed subdomain names,
  no zone transfers, no second DNS-brute-force source (considered and
  explicitly deferred — see below). Processing itself is capped:
  `_MAX_RAW_ENTRIES=2000` response rows parsed, `_MAX_CANDIDATE_HOSTNAMES=200`
  unique in-scope names actually turned into candidates per run.
- **Scope is re-verified independently, not trusted from crt.sh**:
  crt.sh's own search matching is loose (substring-style) — every
  result it returns is re-checked through the *same*
  `is_hostname_in_scope` label-boundary function Step 9.2 built, reused
  unchanged. A wildcard (`*.example.com`) is preserved as evidence but
  **never** becomes a candidate asset. An external name
  (`vendor.example.net`, or the deceptive `example.com.evil.com`) is
  evidence-only and **never contacted** — this provider makes exactly
  one network call, ever, to crt.sh itself, regardless of how many
  external hostnames a certificate happens to mention.
- **A real bug fixed, not sidestepped**: `belongs_to` (the correct
  relationship for "this hostname belongs to this domain") was flagged
  in Step 9.2 as stored backwards — `discovery_normalization_service`
  always made the *seed* the relationship source, but `belongs_to`
  semantically wants the *discovered* thing as source. The only
  production user was the Step 9.1 stub fixture, so the fix was safe and
  contained: `_REVERSED_DIRECTION_RELATIONSHIP_TYPES` in
  `discovery_normalization_service.py` now reverses direction
  automatically for `belongs_to` (and any future type with the same
  child→parent semantic), centralized in the one place that already
  owns "how a candidate becomes a relationship" — no provider needs to
  know about it. Regression-covered (both the corrected direction and
  the general seed→target rule for every other type).
- **Reuses the existing Asset pipeline entirely** — a discovered
  hostname genuinely *is* an `Asset` (unlike Step 9.3's certificates),
  so `discovery_normalization_service.normalize_candidate` needed zero
  changes for hostname creation: `created`/`refreshed` outcomes,
  `status=first_seen`, dedup, and the existing race-safety all just
  work. No new table, no new `DiscoveryResultOutcome` value.
- **DNS-based (second) discovery**: considered per this batch's
  instructions, deliberately not built — it "requires substantial new
  architecture" in the instructions' own words (deduping/correlating a
  second live-evidence source against CT's historical evidence is a
  real design problem, not a quick addition), so it's left for its own
  future step rather than bolted on here.
- **Unicode/IDNA hostnames**: not converted, but not mismatched either —
  `app.core.validation`'s hostname regex is ASCII-only, so a raw Unicode
  CT name is safely *rejected* (`DiscoveryResultOutcome.rejected`) by
  the existing validation once it reaches `normalize_candidate`, rather
  than silently accepted or mis-scoped. Verified with a dedicated test.

**HTTP / Web Intelligence Provider (Step 9.5)** — `POST /discovery/runs`
with `"provider_name": "http"`. **HTTP discovery is bounded intelligence
collection, not vulnerability exploitation or web crawling.** For an
authorized `domain`/`subdomain`/`url` seed, ASM learns whether HTTPS
and/or HTTP respond, what redirects, status code, headers, and (for
HTML) page title they show, conservative technology hints, and whether
any of that changed since the previous observation — never an
exploitation attempt, brute-force endpoint discovery, or crawl.
**HTTP reachability is evidence at the time of observation, not a
permanent guarantee of availability.**

- **No second SSRF implementation.** Reuses
  `app/scanners/http_client.py` directly — the same manually-followed,
  per-hop-`net_safety`-validated, IP-pinned, size/timeout-capped fetch
  layer `headers_module`/`technology_module` already use. The one
  change made to that shared file: the previously-private single-URL
  worker is now the public `fetch_url()` (a pure rename, `fetch()`'s
  own behavior is unchanged) so the provider can call it once per
  scheme and get independent results, plus two purely-additive
  `FetchResult` fields (`redirect_count`, `set_cookie_headers`) neither
  existing caller reads.
- **Independent per-scheme signals, not first-success-wins.** A
  `domain`/`subdomain` seed gets exactly two attempts — `https://{host}/`
  and `http://{host}/` — each reported on its own, so "is HTTPS up"
  and "is HTTP up" never collapse into one answer. A `url`-type seed
  is used exactly as given, one attempt, its own scheme only — never
  broadened into the other scheme or a different host.
- **Redirect scope is checked on top of SSRF safety, not instead of
  it.** `http_client.fetch_url`'s existing redirect loop already
  refuses any private/loopback/link-local/reserved hop — that's
  unconditional and unchanged. This provider adds one more check the
  shared fetch layer deliberately doesn't have (and shouldn't, for its
  existing active-scan callers): the *final* response URL's hostname
  must still be in the seed's authorized scope
  (`app.core.validation.is_hostname_in_scope`). `example.com`
  redirecting to `www.example.com` is followed and fully recorded;
  redirecting to `attacker-controlled.example` is recorded as the fact
  of an out-of-scope redirect only — its headers/title/technology are
  never attributed to the org. Only the final hop is scope-checked (a
  documented limitation, not every intermediate one).
- **What's collected, per scheme**: requested/final URL, status code,
  content type, redirect count, `Server`/`X-Powered-By` headers, page
  title (HTML only), the same six security-relevant headers
  `headers_module` already established
  (`Strict-Transport-Security`/`Content-Security-Policy`/
  `X-Content-Type-Options`/`X-Frame-Options`/`Referrer-Policy`/
  `Permissions-Policy`) as presence booleans, and a cross-reference to
  an already-discovered certificate's fingerprint for HTTPS (read-only
  — never re-fetches or duplicates a `Certificate` row from Step 9.3).
- **Cookies: attributes only, never values.** Every `Set-Cookie`
  header's `name=value` pair (which may be a live session token) is
  discarded before anything is inspected — only `Secure`/`HttpOnly`/
  `SameSite` are parsed and stored. No `Authorization` header, bearer
  token, or response body is ever stored; this is intelligence
  collection, not a packet/body archive.
- **Technology inference is deliberately narrow**, not a reuse of
  `technology_module.py`'s fuller, speculative signature list: `Server`/
  `X-Powered-By` header matches (confidence `0.8`/`0.7`) plus one bounded
  `<meta name="generator">` HTML check (confidence `0.5`) — no claim is
  made without a stated piece of evidence and a confidence value, and no
  large technology-signature database was built.
- **Security headers are facts, not findings.** "HSTS present"/"CSP
  absent" are recorded as-is; nothing here labels a missing header a
  vulnerability — that's the future risk engine's job, kept deliberately
  separate from discovery.
- **Change detection reuses `Observation` as history + current state**,
  the same mechanism Step 9.3 established for certificates — no new
  table. `field_name` is scoped per scheme (`http:https`/`http:http`) so
  the two are tracked independently; a first observation is
  `http_observed`, a later one whose evidence differs is `http_changed`
  (comparing status/server/title/redirect target/security headers/
  technology, not a raw timestamp), an identical re-observation writes
  no new row at all. Two new `ChangeType` values, one new
  `DiscoveryResultOutcome.failed` (a network-level failure — timeout,
  refused, TLS failure — distinct from `rejected`'s validation/scope
  meaning); `observed`/`unchanged`/`refreshed`/`rejected` are all reused
  as-is. One small additive migration (`0010`).
- **No new Asset, no new relationship, ever.** The hostname stays the
  one `Asset`; HTTP characteristics are `Observation` evidence about it,
  never artificial nodes for headers/status/technology/titles, per this
  batch's explicit instruction.
- **Failure handling**: each scheme is attempted and reported
  independently — a TLS failure on `https` doesn't affect the `http`
  attempt or corrupt the run, and a 403/404/500 is recorded as a normal
  observation, never auto-classified as a vulnerability.

**ASN / IP / Network Intelligence Provider (Step 9.6)** — `POST
/discovery/runs` with `"provider_name": "network"`. For an authorized
`ip_address` seed: what ASN/network announces it, what prefix, what its
network organization and registration country are, what reverse DNS
says, and whether it looks like a well-known cloud provider — passive
network intelligence, never active probing.

- **Data source**: [Team Cymru's public IP-to-ASN DNS lookup
  service](https://team-cymru.com/community-services/ip-asn-mapping/) —
  plain DNS TXT queries against a fixed, trusted third party
  (`*.origin.asn.cymru.com`/`*.origin6.asn.cymru.com` for the
  ASN+prefix+country, `AS<n>.asn.cymru.com` for the registered
  organization name), plus a standard PTR lookup for reverse DNS — all
  via `dnspython`, already a project dependency (used by `dns_provider.py`
  since Step 9.2). **No new dependency, no API key, nothing to add to
  `.env.example`.** Exactly like `subdomain_provider.py`'s crt.sh usage,
  this is deliberately *not* routed through `net_safety` — the
  connection destination is always this one fixed DNS service; the seed
  IP is embedded in the query name, never used as a connection target.
- **Defense in depth**: even though a private/loopback/reserved value
  can never become an `ip_address` Asset in the first place (rejected at
  creation time), the provider independently re-checks every seed via
  the same `app.core.validation.validate_ip_address` before making any
  lookup — verified by a test that makes zero DNS calls for an unsafe
  IP, and another that runs the real, unmocked validator against an
  RFC 5737 documentation address.
- **ASN is a real Asset, reusing the existing `AssetType.asn`** (already
  creatable since Step 8) — no new table, no second representation.
  `IP --announced_by--> ASN`, a **new, purpose-built `RelationshipType`**:
  neither the default seed→candidate direction nor `belongs_to`'s
  existing reversal reads correctly here (the seed IP is the semantic
  *child*, the discovered ASN the *container* — the opposite of
  `belongs_to`'s calibrated "discovered subdomain belongs to its seed
  domain" case), so reusing either would have produced a backwards or
  nonsensical relationship. Documented in the enum itself.
- **Prefix, organization, country, registry, PTR, and cloud-provider
  classification are `Observation` evidence on the IP, never separate
  Assets or relationships** — an announced `/24` isn't independently
  actionable the way a hostname or ASN is, and promoting it would
  reopen exactly the over-broad-CIDR risk `max_ip_range_prefix_length`
  exists to prevent. Mirrors Step 9.3/9.5's "evidence over premature
  graph nodes" precedent.
- **Reverse DNS (PTR) is evidence only, *never* a candidate Asset — a
  deliberate, disclosed gap, not an oversight.** DNS/certificate/
  subdomain discovery all scope-check a candidate hostname via
  `is_hostname_in_scope(candidate, seed)`, which does a DNS-label-
  boundary comparison against a *hostname* seed. This provider's seed
  is a bare IP address — there is no hostname authority to compare
  labels against, so that check has no honest meaning here, and
  providers have no DB access to check "does this hostname already
  have its own authorized Asset" instead. Rather than invent an
  unproven scope heuristic, every PTR result is treated the same
  conservative way, unconditionally: recorded as fact, never promoted.
  `unrelated-provider.example.net` (a real example from this batch's
  own instructions) is recorded, never created as an Asset, never
  contacted.
- **What's known vs. what's inferred, kept explicitly separate**: `asn`/
  `asn_organization`/`announced_prefix`/`network_country`/`registry` are
  the network registry's own reported facts; `ptr_hostname` is a
  directly-resolved DNS fact with **no attached ownership claim**;
  `cloud_provider_evidence` is a clearly separate, labeled *inference*
  from the AS organization name string (e.g. `provider=Cloudflare,
  confidence=0.8, evidence="AS organization name matched 'CLOUDFLARE'"`)
  — never blended into `asn_organization`, and never derived from PTR
  alone. ASM does not say "this IP belongs to Company X" merely because
  PTR resolves to `company-x.com`.
- **Confidence model**: one overall confidence per network Observation
  (matching `CertificateObservation`/`HttpObservation`'s own
  granularity — not a separate value per field). `0.9` when an ASN was
  found (a dedicated, purpose-built routing-table mirror — more
  authoritative than a client-controlled header, but a
  periodically-updated third-party mirror, not `dns_provider`'s live
  first-party `1.0`); `0.8` for a partial result where only PTR
  resolved (a directly-resolved DNS fact, but with no network/ASN
  attribution to anchor a higher confidence on). Cloud-provider
  inference carries its own separate, explicit `0.8` inside
  `cloud_provider_evidence` (matching Step 9.5's Server-header
  confidence: a registered AS name is a strong, non-spoofable-by-the-
  client signal) — kept apart from the overall observation confidence
  since it's a distinct inference, not a directly-observed fact.
- **Change detection reuses `Observation` as history + current state**,
  the same mechanism Steps 9.3/9.5 established — no new table. A first
  observation is `network_observed`, a later one whose evidence differs
  (ASN, prefix, organization, PTR, or cloud classification) is
  `network_changed`, an identical re-observation writes nothing new.
  Two new `ChangeType` values, one new `RelationshipType`
  (`announced_by`); `observed`/`unchanged`/`refreshed`/`rejected`/
  `failed` are all reused as-is. One small additive migration (`0011`).
- **Failure handling**: an unsafe seed is `rejected` cleanly (with the
  reason recorded) before any lookup is attempted; a total lookup
  failure (no ASN/prefix and no PTR from any source) is `failed`, a
  normal informative outcome, not a provider malfunction — a single bad
  target never corrupts the run, and a partial result (e.g. ASN found
  but PTR missing, or vice versa) is still fully recorded.

**Cloud & Infrastructure Intelligence Provider (Step 9.7)** — `POST
/discovery/runs` with `"provider_name": "cloud"`. For an authorized
`ip_address` seed: which cloud/hosting provider appears to support it,
with what confidence, and what evidence — correlating signals already
known to ASM rather than probing anything new. **`network` provider ≠
`cloud` provider ≠ asset owner — three explicitly distinct concepts,
never conflated:**

- **Network attribution** (Step 9.6, unchanged): the ASN and network
  registry facts (organization name, country, registry) an authorized
  routing-table mirror reports for this address.
- **Cloud/infrastructure classification** (this step): a
  confidence-scored, multi-signal *inference* about which cloud/hosting
  platform this address is probably on — an ASN belongs to a network
  operator, which may itself *be* a cloud provider (Amazon, Google,
  Cloudflare), a traditional hosting company, a CDN, an ISP, or an
  enterprise running its own network. This step never treats "has an
  ASN" and "is a cloud provider" as the same fact.
- **Asset/organization ownership** — ASM does not claim this anywhere.
  "This IP's infrastructure looks like AWS" is never presented as, or
  silently upgraded into, "this organization's asset is legally owned
  by Amazon" or by anyone else.

- **Seed type: `ip_address` only, by explicit design, not an
  oversight.** `dns_provider`/`http_provider` already turn a
  domain/subdomain/url seed into an `ip_address` Asset (via resolution)
  plus HTTP/TLS evidence on that hostname; `network_provider` already
  turns an `ip_address` seed into ASN/prefix/PTR evidence. Accepting
  domain/subdomain/url here too would mean either re-implementing that
  resolution pipeline or silently picking "the first IP" a domain
  resolves to and hiding which address the classification actually
  describes. The existing, correct pipeline — resolve down to an IP
  first, *then* classify its infrastructure — is preserved as-is.
- **No new network I/O of its own for the strongest signals.** This
  provider composes `NetworkDiscoveryProvider` directly (calling it, not
  re-implementing Team Cymru queries) for ASN/prefix/PTR, and opens no
  HTTP or TLS connection of its own — the Server-header and
  TLS-issuer signals are read from **already-stored** `Observation`/
  `Certificate` rows on hostnames that `resolves_to` this IP (Steps
  9.3/9.5), via `discovery_normalization_service`, which has the DB
  access providers themselves don't.
- **Evidence sources used**: ASN (both the raw number, against a small,
  intentionally incomplete table of well-known primary ASNs, and the
  registered organization-name string), reverse DNS (PTR) pattern,
  stored HTTP `Server` header, stored TLS certificate issuer. **Deferred,
  not built**: provider-published IP range lists (AWS's `ip-ranges.json`
  and equivalents) — fetching, caching, and periodically refreshing
  those is a real, separate subsystem, not bolted on speculatively here
  (mirrors the Step 9.4 decision to defer a "DNS second source" for the
  same reason). Confidence is capped below "certain" specifically
  because this pass has no authoritative range match to lean on.
- **Multiple corroborating signals, never one weak signal as proof.**
  Each signal type is independently weighted by how hard it is to
  spoof (ASN hardest, HTTP header easiest); matching signals for the
  same provider add up, capped at an overall maximum. A PTR containing
  `amazonaws.com` alone yields a *weak* classification on its own — the
  same conclusion backed by a matching ASN and a matching TLS issuer
  too is *confidently* held instead, and the evidence list says exactly
  which signals contributed. Generic CAs (Let's Encrypt, ZeroSSL,
  DigiCert, Sectigo/Comodo) are explicitly excluded as TLS-issuer
  evidence — anyone, on any infrastructure, can use them, so they carry
  zero provider information.
- **Why announced prefix isn't its own classification signal**: the
  prefix and the ASN come from the exact same Team Cymru response —
  not independent evidence, two facets of one fact. Weighting a prefix
  match as a second vote for a provider the ASN signal already voted
  for would double-count that one fact. The prefix is still recorded
  as evidence and still participates in change detection (a prefix
  change is meaningful on its own), just not as an independent
  classification signal.
- **Confidence buckets**, matching the spec's own vocabulary:
  `confidently_identified` (≥0.75), `probably_identified` (≥0.5),
  `weakly_inferred` (>0), `unknown` (0, `provider=None`) — the last is
  a normal, honest, frequently-correct outcome, not a failure.
- **Conflicting signals are recorded, never hidden.** When a runner-up
  provider's evidence is at least 60% as strong as the winner's (e.g.
  ASN says AWS, TLS issuer says Cloudflare — a real, plausible pattern
  for a Cloudflare-fronted origin actually hosted on AWS),
  `conflicting=True` is set and the runner-up's own provider/confidence/
  evidence is preserved in `alternative_providers`, not discarded.
- **No new Asset, no new relationship — a deliberate architecture
  decision, not a gap.** "Probably fronted by Cloudflare" does not
  identify a unique, addressable cloud resource the way a discovered
  hostname or a certificate fingerprint does — there's no ARN, no
  instance ID, nothing stable to key a graph node on, just a
  probabilistic classification of an IP already in the graph. Recorded
  as `Observation` evidence on the IP (mirroring Step 9.6's own
  prefix/organization/country precedent) instead of inventing a
  `cloud_resource` Asset per guess, which would imply a precision this
  evidence doesn't have.
- **Change detection** reuses `Observation` as history + current state
  — no new table. A first classification is `infrastructure_observed`;
  a later one whose provider, confidence, evidence, ASN, prefix, PTR,
  or correlated HTTP/TLS evidence differs is `infrastructure_changed`
  (e.g. "this address moved from AWS to Azure between observations" is
  directly answerable from history); an identical re-observation writes
  nothing new. Two new `ChangeType` values; `observed`/`unchanged`/
  `refreshed`/`rejected`/`failed` are all reused as-is — zero new
  `DiscoveryResultOutcome` values needed. One small additive migration
  (`0012`).
- **Correlation across assets**:
  `discovery_normalization_service.get_shared_infrastructure_groups`
  groups an organization's `ip_address` assets by their most recent
  (provider, ASN) classification — read-time correlation over existing
  Observations, deliberately **not** a stored relationship (two IPs
  that merely share a provider have no direct edge to each other; there
  is nothing concrete to draw an edge between). IPs still unclassified
  or classified `unknown` are excluded from every group, so unknowns
  are never misleadingly clustered together as if they shared
  infrastructure. Not yet exposed as its own REST endpoint — the
  existing `/assets`/`/assets/{id}/observations` endpoints already let
  a client reconstruct this, and a dedicated endpoint is a small,
  additive future addition once a concrete UI need asks for it.
- **Security**: no port scanning, no active probing of cloud IP ranges,
  no contact with any discovered third-party host, no cloud credential
  testing — every signal this step uses was already gathered by an
  existing, already-scoped-and-authorized provider, or is read from
  storage.

**Intelligence Correlation & Attack-Surface Graph (Step 9.8)** — makes
the graph accumulated by Steps 8 and 9.1–9.7 actually queryable for the
first time. **This step adds no new data and no new table** — `Asset`,
`AssetRelationship`, and `Observation` already *are* the attack-surface
graph and its history; Step 9.8 is a pure read/query layer on top of
them, in `app/services/graph_service.py` plus four new `GET` endpoints
on the existing `assets` router. No migration — everything is computed
on demand from existing columns and indexes.

- **`GET /assets/{id}/graph?depth=N`** — the N-hop neighborhood of one
  asset: every asset reachable within `N` hops, plus the *full induced
  subgraph's* edges among them (not merely the edges traversal happened
  to expand through — two sibling nodes that are also directly
  connected to each other show that edge too). Iterative BFS in Python,
  not a recursive CTE: at this codebase's stated per-organization
  scale, a handful of `IN()`-batched queries (one per depth level) is
  simpler to prove correct, test, and keep deterministic than a
  cycle-safe, bidirectional, depth-bounded recursive SQL CTE, and
  nothing has shown a reason to prefer the latter. **Cycle-safe by
  construction**: a node already visited never re-enters the frontier,
  so `A → B → C → A` simply stops contributing new nodes rather than
  looping — proven with a dedicated three-node-cycle test. **Depth is
  hard-capped at `MAX_GRAPH_DEPTH = 5`, server-side, non-negotiable** —
  a request for `depth > 5` (or negative/invalid `depth`) is rejected
  with **HTTP 400, never silently clamped** (an explicit, deliberate
  choice: a client that thinks it asked for depth 8 and silently got
  depth 5 back would draw wrong conclusions from an incomplete graph
  without knowing it). `depth=0` returns just the seed node, no edges.
  Organization isolation is enforced **at every expansion step**, not
  only in the final response — a cross-org relationship can't exist
  today (enforced at write time), but traversal never relies on that
  invariant alone.
- **`GET /assets/activity`** — an organization-wide, chronological feed
  of `Observation`s across *every* asset, the cross-asset counterpart to
  `GET /{id}/observations` (which only ever showed one asset's history).
  `Observation` carries no `organization_id` column by design (see Step
  8) — every query joins through `Asset` for scoping, never assumes
  otherwise. Ordered by `(observed_at DESC, id DESC)` — `observed_at`
  alone isn't a reliable tiebreaker since Postgres's `now()` can produce
  identical timestamps for rows written in the same transaction (seen
  before, in this codebase's own discovery-result ordering). Filterable
  by `since`/`change_type`; `limit` is capped at 200 via FastAPI's own
  declarative `Query(le=200)` at the route, *and* independently capped
  again inside `graph_service.get_activity_feed` itself, so an
  unbounded query isn't possible even if the service function is ever
  called directly, bypassing the route.
- **`GET /assets/summary`** — descriptive inventory statistics: asset
  counts by type/status/criticality, relationship counts by type, total
  and last-7-days observation counts, and an `isolated_asset_count`
  (assets with zero relationships in either direction) as a cheap,
  genuinely useful connectivity statistic. **Computed on demand, not
  cached or materialized** — a whole new "keep this in sync" problem
  class isn't worth avoiding a handful of `GROUP BY` queries at this
  scale. **This is explicitly not a risk score.** No severity is
  computed, no weighting is applied, connectivity is never treated as a
  proxy for risk — a dedicated test asserts the response contains no
  `risk_score`/`risk`/`severity`/`score` field. That's Step 14's job;
  this step only counts what already exists.
- **`GET /assets/shared-infrastructure`** — a thin wrapper exposing the
  already-existing, already-tested Step 9.7
  `get_shared_infrastructure_groups` function via a route, closing the
  one gap that step's own README section explicitly disclosed. The
  grouping logic itself is untouched.
- **Security**: all four endpoints are read-only, reuse the existing
  org-scoping/authentication primitives, and carry no role restriction —
  matching the precedent every existing read endpoint already set
  (`GET /assets`, `.../relationships`, `.../observations` are all
  unrestricted-by-role today; viewers can already read everything, they
  just can't write). No new authorization model was introduced. Route
  registration order matters and was verified explicitly: `/activity`,
  `/summary`, and `/shared-infrastructure` are static path segments one
  level under `/assets`, the identical shape as `/{asset_id}` — they're
  registered *before* that route in `assets.py`, or FastAPI/Starlette's
  registration-order matching would try to parse e.g. `"activity"` as a
  UUID and 422 before ever reaching the intended handler.
- **What Step 9.8 explicitly does not do**: no numeric risk score, no
  risk engine, no asset-criticality write endpoint, no frontend graph
  visualization, no alerting/notifications/remediation, no cached or
  materialized graph table, no graph database, no new discovery
  provider, no relationship-level observation history, **no Web3
  functionality of any kind** — all of these remain explicitly future
  roadmap work, not silently deferred without saying so.

**Change Intelligence & Attack-Surface Monitoring Foundation (Step 9.9)**
— makes discovery's existing history genuinely trustworthy for change
detection, and adds the first disappearance detection in the system.
**This is not continuous monitoring** — discovery still only runs when
explicitly requested; this step builds the intelligence foundation a
future scheduler will need, without adding the scheduler itself.

- **The core problem this closes**: every asset refresh (any re-
  discovery of an already-known asset) used to write an `asset_updated`
  Observation unconditionally, even when nothing had changed — a gap
  disclosed since Step 9.1 ("a candidate for de-duplication once a real
  provider runs on a schedule and produces meaningfully more volume").
  `discovery_normalization_service._refresh_asset` now snapshots an
  asset's *meaningful* state (`value`, `asset_type`, `status`, `source`,
  `environment`, `criticality`, `owner`, `tags`) before and after a
  refresh and only writes an Observation — and only returns
  `DiscoveryResultOutcome.refreshed` instead of `unchanged` — when one
  of those fields actually differs. **`updated_at`/`last_seen`/database
  IDs never count**, and neither does `confidence` — a continuously-
  fluctuating signal-strength value that would reintroduce the exact
  noise this step removes if treated as "state." A plain re-
  confirmation (the common case) is now silent and free; a genuine
  change (most often a stale/disappeared → active revival) writes one
  Observation naming exactly which fields changed, their previous and
  new values. The identical principle now applies to relationships too
  (`asset_relationship_service.create_relationship`): re-confirming an
  already-active relationship writes nothing; reviving one from
  stale/disappeared writes a `relationship_updated` Observation — "a
  relationship that returns" is now directly observable, which it
  wasn't before.
- **Deterministic, canonicalized comparison**
  (`discovery_normalization_service.canonicalize_for_comparison`):
  applied to the asset-state diff above and retrofitted into the three
  existing evidence-comparison functions (`record_http_observation`/
  `record_network_observation`/`record_infrastructure_observation`) —
  dict key order was already comparison-insensitive in Python, but list
  order wasn't; two evidence payloads differing only in list ordering
  (e.g. security-header evidence, cloud-classification signals) now
  correctly compare equal instead of risking a spurious "changed"
  event. Deliberately does not do case normalization or strip
  timestamps — those stay caller-specific decisions (a Server header's
  case might be meaningful evidence; a raw timestamp was already never
  placed in a compared evidence dict, by longstanding convention).
- **Disappearance detection**
  (`discovery_normalization_service.detect_and_mark_disappeared_candidates`,
  called from `discovery_service.execute_run` only after a run reaches
  `completed`, never for a `failed` run): compares a run's reconfirmed
  candidates (`created`/`refreshed`/`unchanged` outcomes) against the
  immediately preceding *completed* run for the same (seed, provider)
  pair. Anything found before but not now has its relationship from
  that seed marked disappeared via the existing, already-tested
  `mark_relationship_disappeared` (soft-remove — status transition,
  never a delete, history fully preserved). The candidate asset's own
  `status` is *additionally* set to `disappeared`, but only once **none**
  of its relationships — from any seed, any provider — remain active:
  an asset independently reconfirmed via a different path is never
  marked disappeared just because one path stopped confirming it.
- **The explicit safety rule, honestly scoped**: "provider failed" and
  "provider succeeded but genuinely didn't find this again" must never
  be confused. A `failed` run (provider malfunction) never reaches
  disappearance detection at all — gated purely on the run's own
  status. A `completed` run that reconfirmed **zero** candidates when
  the previous run found some is treated as suspicious/inconclusive
  (a likely silent partial failure a provider's own "never raise, just
  report nothing" contract can produce, e.g. one DNS record type timing
  out while others succeed) and triggers no disappearance either. **What
  this does *not* solve**, stated plainly: a run that reconfirms *some
  but not all* previously-known candidates due to a genuine partial
  hiccup is indistinguishable, with today's provider return contracts,
  from real partial disappearance — solving that fully would require
  every provider to report per-sub-check success/failure, which is a
  larger, separate change not made here. Documented as a known limit,
  not silently papered over.
- **`GET /assets/activity` is Step 9.9.7's "GET /assets/changes"** — not
  duplicated under a second name. Post-9.9.4, an Observation is only
  ever written for a genuinely meaningful event, so `/assets/activity`
  and a hypothetical separate `/assets/changes` endpoint would be
  functionally identical; building both would violate this batch's own
  "do not create duplicate representations" rule. Extended instead with
  an `asset_type` filter and **keyset pagination**
  (`before_observed_at`+`before_id`, both together, taken from the last
  item of the previous page) — chosen over OFFSET pagination for its
  well-known drift under concurrent writes. "Filter by provider" has no
  dedicated column to filter on (`Observation` carries no
  `provider_name`) — each provider's own `ChangeType` values
  (`http_observed`, `network_changed`, ...) already serve as a natural
  provider filter via the existing `change_type` parameter, so no
  column/migration was added for this. **`GET /assets/{id}/changes` was
  evaluated and deliberately not built either** — `GET /assets/{id}/observations`
  (Step 8) already serves this exact purpose, and its value as a
  "change history" view is directly improved by the 9.9.4 dedup work
  above (fewer, more meaningful rows) with no new endpoint required.
- **No new table, no new migration.** `Observation` (extended with
  better comparison logic) plus the existing `DiscoveryResult` plus
  Step 9.8's activity-feed query pattern already represent everything
  Step 9.9 needed — asset_id, discovery_run_id, change_type, detected_at,
  previous/current state are all already there. No new `RelationshipType`,
  no new `DiscoveryResultOutcome` either — every needed concept already
  existed in the enums (`asset_updated`/`asset_status_changed` for
  changes, `unchanged` for no-ops, `relationship_removed` for
  disappearance, and — notably — `relationship_updated`, defined since
  Step 8 but never actually produced by any code path until now).
- **Future monitoring flow this sets up, not yet built**: `organization
  → authorized seed → provider → discovery run → normalization →
  comparison (this step) → change events → graph update`. A future
  scheduler only needs to periodically call the existing, unchanged
  `discovery_service.create_run`/`execute_run` on a recurring cadence
  per authorized seed — everything downstream (dedup, disappearance,
  change history, the activity feed, the attack-surface graph) already
  works correctly today, synchronously, on every manually-triggered run.
  No Celery scheduling was added in this step, by explicit instruction.

**Risk & Prioritization Intelligence Foundation (Step 9.10)** — answers
"what should the analyst investigate first?" using only intelligence
already collected by Steps 8–9.9. **Risk prioritization here is
contextual and explainable. It is NOT a guarantee of exploitability,
not a vulnerability scanner replacement, not a CVSS replacement, not an
automated remediation engine, and not proof that an attack path is
exploitable.**

- **Deliberately separate from `app/services/risk_engine.py`** (Phase
  1): that module scores *scan Findings* — a numeric, weighted 0–100
  formula over severity/exposure/exploitability, producing a
  `RiskSeverityBand`. `app/services/prioritization_service.py` scores
  *assets*, from *discovery/graph context* — exposure, business
  criticality, change recency, graph connectivity, evidence confidence.
  These are genuinely different inputs answering different questions;
  reusing `RiskSeverityBand` or a weighted-sum shape here would conflate
  two independent signal sources, so this step introduces its own named
  concept, `PriorityLevel` (`informational`/`low`/`medium`/`high`/`critical`),
  rather than overloading the existing one. A future step may
  deliberately unify the two — not decided here.
- **Five explainable dimensions, never one opaque number**: exposure,
  business criticality, change recency, connectivity relevance,
  evidence confidence — each reported as its own qualitative level
  (`none`/`low`/`moderate`/`high`, or `unknown`/`low`/`medium`/`high`/`critical`
  for business criticality). The overall `priority` is derived from a
  small, ordered, human-readable set of rules
  (`prioritization_service._derive_overall_priority`) — not a weighted
  formula — and every rule branch corresponds directly to a reason
  returned in the response. **No numeric risk score was invented** —
  matching this batch's own explicit instruction not to add one simply
  because it's easy to compute.
- **Every priority decision carries machine-readable reasons**: `{signal,
  impact, description, evidence}` per contributing factor — e.g.
  `asset_criticality`, `http_exposed`, `certificate_changed`,
  `connects_to_critical_asset`, `newly_discovered`. An analyst (or
  future UI) can see exactly why an asset was prioritized, not just the
  final label.
- **Missing data is never silently treated as "normal."** No
  `criticality`/`environment` set → `business_criticality="unknown"`,
  never defaulted to `low`; a reason (`unknown_business_context`)
  explicitly says so, and the overall `confidence_label` is downgraded
  to reflect it — the spec's own example, `"High priority, medium
  confidence"`, is directly achievable. `owner`/`tags` are treated as
  descriptive context only, never as scoring inputs (no established
  vocabulary exists for what a tag *means*, so nothing is inferred from
  one). Evidence confidence is the **minimum** numeric confidence among
  every signal that actually contributed to the decision — a single
  low-confidence signal pulls the whole result down, never gets
  smoothed out by averaging with stronger ones.
- **Change-context signals reuse Step 9.9's dedup work directly**:
  `certificate_changed`/`http_changed`/`infrastructure_changed`/
  `network_changed`/`asset_status_changed` (revival) Observations within
  a 24-hour window (`RECENT_CHANGE_WINDOW`, a plain module constant —
  same precedent as `graph_service.MAX_GRAPH_DEPTH` — not a new Settings
  field) drive `change_recency`. **DNS is the one exception, handled
  honestly**: `dns_records_observed` has no `_changed` counterpart (Step
  9.2's `record_seed_evidence` was never given comparison-based dedup,
  and this step doesn't add it) — so `prioritization_service` compares
  the two most recent `dns_records_observed` rows itself, read-only,
  using the same `canonicalize_for_comparison` Step 9.9 already built
  and proved trustworthy, rather than claiming a "DNS changed" signal
  the underlying data can't actually support without it.
- **Graph relevance stays conservative, on purpose**: reuses the exact
  relationships already in `AssetRelationship` (no new graph
  architecture) to compute a relationship count and whether the asset
  connects to a high/critical-criticality neighbor. Called
  `connectivity_relevance`, never "attack path" — every reason
  mentioning a connected critical asset explicitly says *"potential
  attack-surface relevance, not a proven exploit path."* No
  betweenness/bridge/centrality graph algorithm was built — a
  genuinely more complex feature this step's conservative framing
  doesn't call for.
- **Nothing is persisted.** `PriorityLevel` and every dimension are
  computed fresh on every call from current `Asset`/`AssetRelationship`/
  `Observation` data — never cached, never a stored column, so nothing
  can go stale. Confirmed no migration was needed at all: `PriorityLevel`
  isn't even a Postgres-backed enum (unlike every enum in
  `app/core/enums.py`), it's a plain Python enum living in
  `prioritization_service.py` itself, since it will never back a DB
  column.
- **Batched, not N+1**: `prioritize_assets` issues a fixed, small number
  of queries (asset list, observations, relationships, neighbor
  criticalities, certificate presence) regardless of how many assets are
  being evaluated — proven by a dedicated test counting actual SQL
  statements at two different asset-count sizes. Zero active network
  requests are ever made — proven by a test that makes `httpx`/DNS calls
  raise if invoked during evaluation.
- **`GET /assets/prioritized`** (organization-wide, filterable by
  `asset_type`/`environment`/`criticality`/`priority`, bounded `limit`,
  deterministic ordering: priority descending, then asset value
  ascending) and **`GET /assets/{id}/risk`** (single-asset detail) —
  both new, since neither the existing `/assets/summary` (aggregate
  counts, a different response shape entirely) nor `/assets/activity`
  (chronological events, not a ranked/explained asset list) could
  cleanly absorb this without becoming a different endpoint in
  disguise. Both share the identical underlying evaluation function, so
  the list and single-asset views can never disagree — proven by a
  dedicated consistency test. No role restriction, matching every
  other read endpoint's precedent.

**Continuous Monitoring & Discovery Orchestration (Step 9.11)** — makes
discovery operationally usable as a recurring, unattended process
instead of something only ever triggered manually. **This is not an
intelligence provider** (no new signal is discovered) and **not a
general-purpose scheduler** — it is a deliberately boring, narrow
orchestration layer over the exact `discovery_service.create_run`/
`execute_run` pair every prior discovery step already built and proved
correct.

- **`DiscoverySchedule`** (new model, migration `0013`): `seed_asset_id`
  + `provider_name` + a plain-integer `interval_hours` (**not cron** —
  no expression parser, no timezone-of-schedule handling, matching the
  explicit "keep this boring" instruction). `next_run_at` is the single
  source of truth for due-ness; `claimed_at` plus `DiscoveryRun.status`
  together are the concurrency-safety mechanism (see below) — there is
  deliberately no separate `claim_token` column. An earlier draft
  included one; it was removed once it became clear `DiscoveryRun`'s own
  `queued`→`running` transition, using the exact atomic-conditional-
  `UPDATE` pattern `scan_executor.py` already established, already fully
  serializes duplicate execution — a second, parallel claim concept
  would only have been redundant state to keep in sync.
- **Two independent atomicity boundaries, not one**: (1) claiming the
  *schedule* — `discovery_scheduler_executor.claim_due_schedules` uses
  `SELECT ... FOR UPDATE SKIP LOCKED` to pull a batch of due, unclaimed
  schedules and create their `DiscoveryRun` rows in the same
  transaction, so two concurrent dispatch ticks (or a dispatch tick
  racing a manual trigger) can never both win the same schedule; a
  single-row equivalent, one atomic conditional `UPDATE`, backs the
  manual-trigger path (`claim_schedule_now`, returns `None` on a lost
  race → the route reports `409`). (2) claiming the *run* — even if the
  same `run_id` were ever dispatched twice (a redelivered Celery
  message, two workers), `execute_scheduled_run` only proceeds past an
  atomic `UPDATE discovery_runs SET status='running' WHERE id=X AND
  status='queued'`; the loser's `UPDATE` affects zero rows and it
  returns cleanly without touching the provider a second time. **Not
  proven by mocks** — `tests/test_discovery_scheduler_concurrency.py`
  races real `threading.Thread`s, each on its own database session,
  against a real Postgres instance for all four combinations (dispatch
  vs. dispatch, dispatch vs. manual, manual vs. manual, execute vs.
  execute), the same pattern `test_scan_race_safety.py` already
  established for scans.
- **Authorization is re-checked at execution time, not assumed from
  creation time.** No new "scheduled authorization" concept was
  invented — `Asset.authorization_confirmed` was already persisted,
  revocable authorization; a schedule just means real time passes
  between when a run is created and when it executes, so
  `execute_scheduled_run` calls the exact same
  `discovery_service.validate_discovery_request` the manual/API path
  already calls, immediately before doing any work. A revocation (or
  deactivation) that happens after a schedule was created but before its
  next tick fires is caught here — the run is marked `failed` with an
  explicit `error_message`, and **the schedule is also auto-disabled**
  (`enabled=False`, `disabled_reason` set) so it stops repeatedly
  failing on every future tick instead of just failing once silently.
  Live-verified against the real dev stack, not just unit-tested: a
  schedule was created and manually triggered (completed normally,
  `next_run_at` correctly advanced by `interval_hours`), authorization
  was then revoked on the same asset via the real
  `POST /assets/{id}/revoke-authorization` endpoint, the schedule was
  triggered again, and the resulting run reached `failed` with the
  expected message while the schedule flipped to `enabled=false` — a
  subsequent trigger attempt then correctly returned `400`.
- **Failure/timeout semantics preserve Step 9.9's disappearance-
  detection safety exactly.** `reap_stale_runs` (called at the start of
  every dispatch tick) marks any `DiscoveryRun` stuck in `running` past
  `STALE_CLAIM_TIMEOUT` (10 minutes — deliberately longer than the
  execution task's own `soft_time_limit`/`time_limit` of 270s/300s) as
  `failed`, never `completed`, and releases its schedule's claim. Every
  other failure/skip path inside `execute_scheduled_run` (missing seed,
  revoked authorization, unmet dependency, an unhandled provider
  exception) likewise only ever reaches `failed` or `cancelled` — never
  `discovery_service.execute_run`'s own success branch, which is the
  *only* code path that calls
  `detect_and_mark_disappeared_candidates`. A dedicated test proves this
  by comparing `AssetRelationship` state before/after a reaped run:
  nothing is marked disappeared.
- **Minimal dependency mechanism, not a DAG.**
  `DiscoveryProvider.depends_on: ClassVar[set[str]]` is a soft,
  orchestration-level hint (currently only
  `CloudDiscoveryProvider.depends_on = {"network"}`, since network
  discovery is what actually creates the ASN asset/relationship cloud
  classification reads) — `_dependency_satisfied` is a plain existence
  check ("has this provider ever completed successfully for this exact
  seed"), not a live blocking gate, not cycle detection, not a
  scheduling-order guarantee across schedules. An unmet dependency marks
  the run `cancelled` (distinct from `failed` — this isn't an error) and
  releases the schedule's claim immediately so the very next dispatch
  tick retries, rather than disabling the schedule.
- **Enqueue, never inline execution.** `POST /discovery/schedules/{id}/run`
  claims the schedule synchronously (so a lost race is reported as `409`
  immediately) then calls `.delay(...)` and returns `202` with the new
  run's `status="queued"` — the actual provider call happens later, in
  the worker. Live-verified: the response was observed to report
  `queued` immediately under the real (non-eager) Celery broker, with
  the run only reaching `completed` a couple of seconds later once the
  real worker picked it up.
  Task arguments are bare `run_id`/`schedule_id` UUID strings only — no
  secrets, no asset values, no provider objects cross the Celery
  boundary.
- **`GET/POST/PATCH/DELETE /discovery/schedules`** (+ `POST
  /discovery/schedules/{id}/run`) — standard CRUD plus the manual
  trigger, all org-scoped, IDOR-tested (cross-org access to any of the
  five schedule endpoints 404s, never leaks existence), RBAC-restricted
  the same way schedule/run creation already was (`admin`/`analyst` can
  write, `viewer` is read-only). No new history/observability system —
  schedule state (`last_run_at`/`last_run_id`) points at the exact same
  `DiscoveryRun`/`DiscoveryResult` records every other discovery path
  already produces; `GET /discovery/runs/{id}` needed no changes at all
  to show a scheduled run.
- **`beat` is a new, required Compose service** — a `celery beat`
  process ticking `dispatch_due_discovery_schedules` every 60 seconds.
  Explicitly documented (in `docker-compose.yml` itself) as never to be
  scaled beyond one replica, unlike `worker` — Celery Beat is not
  designed for multiple concurrent schedulers, and correctness here
  never depended on Beat being singly-instanced anyway (the schedule/run
  claim mechanisms above are safe even if it accidentally were).
- **Known limitations, stated honestly, not hidden**: `interval_hours`
  is plain-integer hours, not a cron expression — no "every Monday at
  9am," no timezone-aware scheduling. There is no schedule-level
  concurrency cap across an organization (an org with many schedules
  firing at once will enqueue that many Celery tasks; acceptable at
  current scale, a future rate-limit/backpressure concern if that
  changes). The dependency mechanism only checks for a *prior successful
  completion*, not for staleness — a `network` run from months ago still
  satisfies `cloud`'s dependency today. There is no UI, no alerting, and
  no notification on schedule failure beyond the `disabled_reason` field
  itself — an operator must poll `GET /discovery/schedules` to notice a
  disabled schedule; genuine alerting is explicit future work (Step
  9.12), not attempted here.

**Alerting & Change Notifications (Step 9.12)** — turns the change/
prioritization intelligence Steps 8-9.11 already produce into an
actionable alert. **This is not a second change-detection system**:
alerts are generated by reading `Observation` rows the existing
normalization pipeline already writes, never by re-diffing anything.
**Observation = "what happened." Alert = "this deserves attention."**
A routine unchanged observation was never going to become an
Observation in the first place (Step 9.9's dedup already ensures
that); this step's own job is deciding which of those genuine changes
also clears an explicit bar.

- **A small, fixed taxonomy — 10 types, each backed by a real,
  already-existing signal**: `new_externally_exposed_asset`,
  `important_asset_disappeared`, `important_asset_reappeared`,
  `certificate_changed`, `dns_infrastructure_changed`,
  `http_security_posture_changed`,
  `infrastructure_classification_changed`,
  `high_priority_asset_detected`, `authorization_disabled`. **One
  candidate type was investigated and deliberately NOT built**:
  `critical_asset_changed`, keyed on `ChangeType.asset_updated`.
  `discovery_normalization_service._refresh_asset` only ever mutates
  `last_seen`/`confidence`/`status` on an existing asset, so its own
  before/after diff can never actually detect a `value`/`asset_type`/
  `source`/`environment`/`criticality`/`owner`/`tags` change (there is
  still no write endpoint for those fields at all — the same disclosed
  gap since Step 8.1/9.5) — only a status transition, which is already
  the dedicated `important_asset_reappeared` type. Shipping a type with
  no reachable trigger would have violated this taxonomy's own "only
  types backed by actual existing intelligence" rule, so it was cut
  rather than kept as dead code — found and fixed during this step's
  own testing, not left in.
- **Every type but one is Observation-sourced**; `authorization_disabled`
  is the sole exception — a scheduler-level safety event (Step 9.11's
  existing auto-disable-on-revoked-authorization behavior), hooked
  directly into `discovery_scheduler_executor.execute_scheduled_run` at
  the exact point a schedule disables itself, not a discovery-content
  event.
- **Alert generation safety (the critical constraint)**: alert
  evaluation (`alert_service.evaluate_run_for_alerts`) only ever reads
  Observations the existing pipeline already wrote for assets an
  already-org-scoped, already-authorization-checked discovery run
  genuinely touched. A scope-rejected candidate (e.g. an out-of-scope
  certificate SAN, a private-IP candidate) becomes a `rejected`
  `DiscoveryResult` with no `resulting_asset_id` — explicitly excluded
  before alert evaluation ever sees it, proven by a dedicated test.
  Called exactly once, synchronously, at the same point in
  `discovery_service.execute_run` Step 9.9's disappearance detection
  already runs — **after** the run reaches `completed`, meaning a
  failed run, and a zero-candidates suspicious run (Step 9.9's own
  silent-partial-failure guard), can never produce a disappearance
  alert, inherited for free rather than re-implemented. The whole call
  is wrapped in try/except: a bug in alerting can never turn a
  successful discovery into a failed one.
- **Priority reuses Step 9.10's prioritization intelligence directly —
  never a second formula.** Each alert's priority is the max of a
  small per-type baseline and the asset's own computed `PriorityLevel`
  (via a single **batched** call to `prioritization_service.
  prioritize_assets(asset_ids=...)` — see Performance below). Two
  types (`important_asset_disappeared`/`reappeared`) additionally
  require the asset to carry an explicit `criticality` or `environment`
  value before firing at all — Step 9.10.4's "unknown business context
  must remain unknown" applied identically here; a disappearance on an
  unclassified asset is still fully visible via the existing activity
  feed, just not promoted to an alert without a stated reason to care.
- **Deduplication is a deterministic, semantic fingerprint** —
  `sha256(organization_id | alert_type | identity)`, never a
  timestamp or database id. `identity` is the event's own identity:
  an asset id alone for asset-lifecycle types, `+ a slot` (e.g.
  `hostname:443`) for per-slot technical types (certificate/HTTP/
  infrastructure), matching how `Observation.field_name` already
  scopes those signals. The dedup lookup only ever matches an
  **open or acknowledged** alert — a **resolved** one is invisible to
  it, so the identical condition recurring after resolution creates a
  genuinely new row (new id, fresh `first_seen_at`), leaving the
  resolved row's history untouched, never resurrected or overwritten.
  A repeat of the *same still-open* condition updates that row's
  `last_seen_at`/`occurrence_count`/evidence in place — priority is
  only ever raised on such an update, **never lowered**, so a
  once-critical alert can't quietly downgrade just because a later
  observation looked milder.
- **Real PostgreSQL-enforced concurrency, not Python locking**: a
  partial unique index, `uq_alerts_org_fingerprint_open` on
  `(organization_id, fingerprint) WHERE status != 'resolved'`, is what
  actually prevents two concurrent evaluations from creating duplicate
  open alerts — application code catches the resulting `IntegrityError`
  and falls back to the update path (mirroring
  `discovery_normalization_service._get_or_create_asset`'s identical
  SAVEPOINT pattern). **A genuine bug was found and fixed by a real
  3-thread concurrency test during this step**: an early version read
  `occurrence_count` in Python and wrote back `+ 1` without a row lock
  — two concurrent "loser" threads both read the same starting value
  and one increment was silently lost. Fixed with `.with_for_update()`
  on both the initial and the post-conflict lookup, serializing
  concurrent updaters through a real row lock; re-verified with the
  same 3-way race, now correct.
- **Lifecycle: open → acknowledged → resolved**, plus open →
  resolved directly (skipping acknowledgement is a valid workflow).
  **No `reopen` endpoint was built** — a deliberate scope decision: the
  fingerprint mechanism already lets a resolved condition's genuine
  recurrence create a fresh alert, so a manual reopen would add a
  second state-transition surface (more to secure, more to test) for
  marginal benefit over just waiting for the next real occurrence.
- **No second activity-history system.** Alert lifecycle events
  (creation, acknowledgement, resolution) are **not** written into the
  `Observation`-based activity feed — an acknowledgement is a human
  action on ASM's own derived record, not a fact ASM observed in the
  world, so forcing it into `Observation`'s shape would be a category
  error. An `Alert` row's own timestamps (`first_seen_at`/
  `last_seen_at`/`acknowledged_at`/`resolved_at`) already are its
  complete lifecycle history — no separate audit table, matching
  `DiscoverySchedule`'s identical choice (Step 9.11) to track its own
  history inline.
- **`GET /alerts`** (filterable by `status`/`priority`/`alert_type`/
  `asset_id`, keyset-paginated via `before_last_seen_at`+`before_id`,
  ordered `last_seen_at DESC, id DESC` — the identical deterministic-
  pagination shape `GET /assets/activity` already established),
  **`GET /alerts/{id}`**, **`POST /alerts/{id}/acknowledge`**,
  **`POST /alerts/{id}/resolve`** — all org-scoped, IDOR-tested.
  `viewer` can read; `admin`/`analyst` can acknowledge/resolve,
  matching the existing schedule/run write-role convention.
- **Notification channels: in-app/API state (required, always on) +
  email (optional, config-gated, off by default)**. Email uses
  Python's stdlib `smtplib` against configurable SMTP settings — zero
  new dependency. `Settings.alert_notification_email_enabled=False` by
  default means a deployment that hasn't configured SMTP never even
  creates an `AlertNotification` row, so nothing is ever left pending
  indefinitely. Recipients are every active `admin` in the alert's
  organization (no per-user notification-preference concept — an
  explicit non-goal, matching how `owner`/`tags` have no established
  vocabulary either). The email body carries only title/description/
  priority/type/timestamps/occurrence count — **never the alert's full
  `evidence` blob** — proven by a dedicated test.
- **Background delivery, decoupled from discovery.** Alert *rows* are
  written synchronously and cheaply (DB-only, no network I/O) inside
  `execute_run`; only the actual SMTP send is offloaded to Celery
  (`deliver_alert_notification_task`, mirroring `scan_tasks`/
  `discovery_schedule_tasks`'s identical thin-wrapper shape).
  Notifications are queued **only after** `execute_run`'s own commit
  succeeds — never for an alert that might not durably exist — and
  only for **newly created** alerts, never for a deduplicated update,
  which is what keeps a schedule repeating an unchanged condition from
  spamming an inbox, not just from spamming the `Alert` table.
- **Retry safety**: `AlertNotification.status` transitions
  (`pending`/`sending` → `sent`/`failed_transient`/`failed_permanent`)
  via the same atomic-conditional-`UPDATE ... WHERE status IN (...)`
  pattern used everywhere else in this codebase — a retried/duplicate
  Celery dispatch for the same notification finds zero rows to claim
  and returns `'skipped'` without sending twice, proven by a dedicated
  idempotency test. `smtplib.SMTPRecipientsRefused`/
  `SMTPAuthenticationError`/`SMTPSenderRefused` are treated as
  permanent (retrying won't help); everything else network/protocol-
  related is transient and retried up to `MAX_ATTEMPTS=3`, then
  becomes permanent. The task's only argument is a bare
  `notification_id` UUID string — SMTP credentials and recipient
  addresses are read fresh from `Settings`/the database inside the
  worker, never passed as Celery task arguments. One test proves
  delivery against a genuine local, unmocked TCP socket speaking
  minimal SMTP — not just a mocked `send_email`.
- **N+1 avoidance — a real one was found and fixed.** An early version
  called `prioritization_service.get_asset_priority` (the single-asset
  variant) once per touched asset, and again per qualifying
  observation — a genuine N+1 a dedicated query-count test caught
  scaling with candidate count. Fixed by adding an `asset_ids` filter
  to `prioritize_assets` (Step 9.10's already-batched entry point) and
  computing priority for every touched asset in **one** call per run,
  reused throughout evaluation. Verified flat (not growing per touched
  asset) by re-measuring the identical scenario at two different
  scales.
- **No migration surprises**: new tables `alerts`/`alert_notifications`
  (migration `0014`), new enums `alert_type`/`alert_priority`/
  `alert_status`/`notification_channel`/`notification_status`. Upgrade/
  downgrade/re-upgrade verified against the live dev DB.
- **Known limitations, stated honestly**: no Slack/Discord/Teams/SMS/
  push/SIEM/SOAR integration (explicit non-goals); no per-user
  notification preferences; no `reopen` endpoint (see above); the
  dependency-style "has this ever succeeded" staleness gap already
  disclosed for Step 9.11's schedule dependencies applies identically
  to `high_priority_asset_detected`'s own inputs; an ASN/prefix change
  that doesn't also change the cloud-provider *classification* is
  captured in the activity feed and prioritization but does not itself
  raise a dedicated alert (only `infrastructure_classification_changed`
  does) — a deliberate, narrower scope than "every network_changed
  Observation," to avoid an 11th type with weaker signal.

**Customer-Facing Intelligence Dashboard (Step 9.13)** — productization:
ASM is now usable entirely through the UI, without a developer manually
calling API endpoints. **No new backend intelligence, no second
change-detection/graph/risk system** — every page is a thin
presentation layer over the eight prior discovery/graph/prioritization/
alerting steps' existing, already-tested endpoints.

- **Genuinely missing backend capability, added as the smallest
  additive change, not a redesign**: (1) `GET /assets` grew optional
  server-side `asset_type`/`status`/`environment`/`criticality`/`search`
  filters + keyset pagination (`after_value`+`after_id`) — `limit` has
  **no default**, so every existing caller (the pre-9.13 frontend, ~20
  backend tests) that never passed one keeps getting the full unbounded
  list exactly as before; pagination only activates when a caller opts
  in. (2) `GET /discovery/providers` — a pure read over the existing
  provider registry (Step 9.11), added so the schedule-creation form
  doesn't have to hand-mirror provider names/seed-type compatibility
  client-side (the same drift risk already logged as debt for the Scans
  module picker). (3) `AlertRead`/`DiscoveryScheduleRead` gained
  denormalized `asset_value`/`asset_type` (and `last_run_status` for
  schedules), read from their already-existing ORM relationships
  (eager-loaded on the list endpoints specifically to avoid N+1) —
  mirrors `ActivityFeedItem`'s identical, pre-existing precedent for
  the same "a list of X is useless without knowing which asset it's
  about" problem. No migration — every change is a query/read-model
  addition, no new columns.
- **A persistent app shell that didn't exist before this step.** Every
  page used to be its own island (no nav, no shared header) — `AppShell`
  now wraps every authenticated route via one parent layout route in
  `routes.tsx`, with navigation grouped to literally read as
  **Discover → Understand & Prioritize → Act → Operate**, the same
  framing this step's own spec used. `RequireAuth`/`RequireRole` still
  gate the identical subtree they always did — only *how* the JSX tree
  composes pages changed, not what protects them (proven by a dedicated
  route-composition test, since this was a genuine structural change).
- **One new dependency: `d3-force`** — chosen deliberately as the
  smallest sensible option for the attack-surface graph requirement.
  No prior chart/graph/icon library existed in this project at all. It
  is layout-only (no canvas/WebGL/DOM opinions of its own): a
  deterministic force simulation is ticked to completion once, then
  rendered as plain SVG owned entirely by React — every node is a real
  `<g role="button">` with normal click/keyboard handlers, so
  click-to-inspect needed no canvas hit-testing.
- **Attack Surface Explorer** (`/assets`, replaces the old unfiltered
  list): every filter is a server-side query parameter now, not a
  client-side `.filter()` over an unbounded fetch — the one thing this
  step's spec explicitly asked not to do "if the backend can support
  it." Pagination uses `useInfiniteQuery` (TanStack Query's own
  purpose-built tool for keyset "Load more" accumulation — not a new
  library, just a different hook from the one already used everywhere).
  The **Priority** column is filled in best-effort by joining
  `GET /assets/prioritized`'s own already-computed result by asset id —
  never a client-computed priority; capped at that endpoint's own
  200-row max, a disclosed limitation for larger organizations, not a
  second scoring path.
- **Asset Intelligence Detail** (`/assets/:id`): now also shows
  priority + its explanation (`GET /assets/{id}/risk`, reused verbatim),
  relationships (`GET /assets/{id}/relationships`), recent changes
  (`GET /assets/{id}/observations`), and the attack-surface graph, none
  of which the pre-9.13 page exposed at all despite the endpoints
  already existing since Steps 8–9.10.
- **Attack-surface graph**: `GET /assets/{id}/graph` (Step 9.8, still
  completely unmodified) with a depth selector (0–5, matching
  `MAX_GRAPH_DEPTH`), click-to-navigate between assets, and explicit
  loading/error/empty states independent of the rest of the page. No
  new backend graph architecture, no graph database — the existing
  BFS-traversal endpoint is the only data source.
- **Change Timeline** (`/changes`) and **Alert Center** (`/alerts`,
  including acknowledge/resolve) and **Prioritized Assets**
  (`/prioritized`) and **Continuous Monitoring** (`/monitoring`,
  including create/edit/enable/disable/delete/manually-trigger a
  schedule with live run-status polling) — each a direct, thin UI over
  its already-existing, already-tested Step 9.8–9.12 endpoint, adding
  no business logic of its own.
- **A real bug found and fixed by testing, not shipped**: an early
  version of the Monitoring page's per-row delete confirmation rendered
  `ConfirmDialog`'s `position:fixed` overlay `<div>` directly inside
  `<tbody>`/`<tr>` — invalid HTML table nesting, caught by a React
  `validateDOMNesting` warning surfaced during a test run. Fixed by
  lifting delete-confirmation state to the parent page (one shared
  dialog outside the `<table>`, parameterized by whichever schedule is
  pending deletion) rather than one dialog instance per row.
- **Security preserved, not re-implemented**: every RBAC-in-UI check
  (`const canX = user ? ROLES.has(user.role) : false`) is the existing,
  established UX-only pattern this codebase already uses everywhere —
  the real boundary stays server-side `require_role()`, unchanged.
  Organization scoping is never client-supplied: every new page reads
  data the backend already scoped to `current_user.organization_id`
  before it ever reaches the browser. No secret ever crosses into a
  new page (alert evidence/description already excluded secrets at the
  Step 9.12 backend layer, reused verbatim here).
- **Live-verified end to end, not just unit-tested**: registered a real
  user, confirmed the Vite dev proxy (and the equivalent production
  nginx `location` regex, both updated to include `/discovery` and
  `/alerts`, previously missing entirely) correctly reaches the real
  backend for both an unauthenticated request (401, proving the proxy
  path exists and auth is enforced) and an authenticated one (200 with
  real data) against `GET /discovery/providers` and `GET /assets/summary`.
- **Known limitations, stated honestly**: the Explorer's priority
  column and the graph's neighbor-count are both bounded by their
  underlying endpoints' own existing caps (200 assets, `MAX_GRAPH_DEPTH`
  hops) — not something this step changed or worked around. No visual/
  interactive browser verification was performed (no browser/screenshot
  tool available in this environment) — verification is automated
  tests (285 frontend + 709 backend, all passing), a clean production
  build, and real HTTP calls through the actual dev proxy into the real
  backend, not a human or automated click-through of the rendered UI.

**Asset business context (Stage A.1)** — criticality and environment,
the two human-set inputs prioritization reads, are now editable. No new
model, table, migration or dependency.

- **`PATCH /assets/{id}`** (admin/analyst; a viewer gets 403; another
  organization's asset is a 404) accepts only `criticality` and/or
  `environment`, each an existing enum value or `null` to clear it. Any
  other field (identity, organization, authorization, lifecycle,
  discovery evidence) is a 422, never silently ignored, as is an empty
  body. Authorization still changes only through
  `confirm-authorization`/`revoke-authorization`.
- **Recorded atomically**: a change writes an `asset_updated`
  Observation (`field_name="asset_state"`, before/after JSON of just the
  changed fields, the shape discovery's asset refreshes already use) and
  an `asset.update` audit entry, committed with the change in one
  transaction. An update that changes nothing writes nothing.
- **Priority follows on the next read**: `GET /assets/{id}/risk` and
  `GET /assets/prioritized` compute from the stored values on demand, so
  there is no second scoring path or cache to update.
- **UI**: the Asset Detail page's Identity section shows both values;
  admins and analysts get selects and Save, viewers read only. A save
  refreshes the asset's priority, change history and graph, plus the
  asset lists, prioritized list, activity feed and summary.

### SSRF hardening

`app/scanners/net_safety.py` resolves a target hostname (all A/AAAA
records, not just the first) and rejects it if *any* resolved address is
loopback, private, link-local, multicast, reserved, or unspecified —
including IPv4-mapped IPv6 forms, a known real-world filter-bypass
technique that a naive check misses. `app/scanners/http_client.py` builds
on that: redirects are followed manually (never via httpx's automatic
following) and capped, with every hop re-validated the same way before
being followed; responses are streamed with a hard byte cap regardless of
declared `Content-Length`; only a small allowed port set is permitted.
`app/discovery/http_provider.py` (Step 9.5) is a new consumer of this
same layer, not a second implementation of it — it calls the now-public
`fetch_url()` directly and adds only an authorization-*scope* check
(distinct from SSRF safety) on top, since discovery's redirect-following
concerns differ from an already-authorized active scan's.

**DNS-rebinding / TOCTOU is closed, not just disclosed.**
`app/scanners/pinned_transport.py` forces every connection's TCP layer to
use the exact IP address `net_safety` already resolved and validated —
httpx/httpcore never get to re-resolve the hostname themselves, so there
is no second, unvalidated lookup for a rebinding-capable resolver to
answer differently. This works because httpcore treats "which address to
dial" (`connect_tcp(host, port)`) and "which hostname to verify the TLS
certificate against" (`start_tls(server_hostname=...)`) as two separate
steps — pinning only overrides the first. TLS hostname verification is
therefore unaffected: pin a connection to the wrong IP and the handshake
still fails with a certificate-hostname-mismatch error, proven in
`tests/test_tls_pinning.py` against a local self-signed server (a real
attempt to prove this against a live public IP — Cloudflare's `1.1.1.1`
— unexpectedly *succeeded*, because that shared anycast IP also happened
to terminate TLS for an unrelated customer's domain literally named
`example.com` via a custom-hostname feature; real third-party
infrastructure turned out to be the wrong tool for a deterministic
negative test, not just a slow one). `tests/test_dns_rebinding.py`
separately proves the rebinding scenario itself: DNS answering safely on
the first lookup and unsafely on any later one, confirming the
implementation never performs that later lookup at all.

### Asset scope model, subprocess policy

Unchanged from Phase 1 — see inline docs in `app/core/validation.py` and
`app/models/asset.py`. Still no subprocess/shell calls anywhere in the
codebase.

## Architecture

```
Frontend (React SPA) -> nginx (TLS, prod only) -> FastAPI backend -> Scanner engine -> Risk engine -> Reporting -> PostgreSQL
                                                          |
                                                     Celery + Redis
                                                   (async execution)
```

### Why Celery + Redis (not `BackgroundTasks`) for async execution

Phase 1 ran the whole scan pipeline synchronously inside the request. That
stopped being viable once passive-HTTP modules (technology fingerprinting,
security headers) and PDF report generation were added on top of
WHOIS/DNS/TLS — more network calls per scan, no retry story, and no way to
scale scan throughput independently of the API process. Celery gives us
persisted task state, bounded automatic retries for transient failures,
and independently-scalable workers; `redis` was already provisioned in
`docker-compose.yml` in Phase 1 specifically for this.

**Complexity this introduces**: a new long-running process (`worker`) that
must be running for scans to ever leave `queued`; a worker-process DB
session that can't be the request-scoped one FastAPI hands routes (see
`scan_executor.execute_scan`, which always opens its own session); and a
second place authorization has to be checked, since time now genuinely
passes between "scan requested" and "scan executed" (see the disclaimer
above).

**How workers are started**: `docker compose up -d worker` — same image as
`app`, different command (`celery -A app.celery_app worker`). Scale by
running more worker containers; no code changes needed.

**How scan status is persisted**: unchanged `ScanStatus` enum
(`queued → running → completed/failed`, now also `cancelled`), just
written by `scan_executor` instead of directly by the route handler.

**Failures/retries**: authorization/validation errors (unconfirmed asset,
unknown module) are still caught synchronously in the route before
anything is queued — a client gets an immediate 403/400 exactly like
Phase 1, never a queued-then-silently-failed scan for those cases.
Once queued, `execute_scan_task` (`app/tasks/scan_tasks.py`) retries up to
twice with backoff on any unexpected exception (DB hiccups, bugs) — it's
deliberately a thin wrapper; all real logic is in
`app/services/scan_executor.py`, so retries just re-run that function
from scratch, including its authorization re-check.

**Testing**: `celery_task_always_eager` defaults to `False` everywhere,
including tests — matching real deployment behavior rather than a
convenient-but-unrealistic default. Tests that need deterministic,
synchronous completion opt in explicitly via the `eager_celery` pytest
fixture. A separate integration test
(`tests/test_celery_integration.py`) exercises the real broker/worker
over actual HTTP against the persistent `app`/`worker` services. Because
it writes to the development database and runs a real DNS scan, it is
**opt-in**: skipped unless `ASM_RUN_LIVE_STACK_TESTS=1` is set, and once
opted in an unreachable stack is a hard failure, not a skip. See
"Running tests" below.

## Tech stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2.0, Alembic
- **Frontend**: React 18, TypeScript, Vite, TanStack Query, Tailwind,
  React Router, `d3-force` (attack-surface graph layout, Step 9.13)
- **DB**: PostgreSQL 16
- **Async**: Celery 5 + Redis (broker and result backend)
- **Reporting**: `reportlab` (PDF), stdlib `csv`/`json`
- **Auth**: JWT (access + refresh) delivered via httpOnly cookies (never
  a response body), double-submit CSRF protection, refresh-token
  rotation + revocation, Redis-backed account lockout, RBAC (`admin` /
  `analyst` / `viewer`) — see [`docs/auth-cookie-model.md`](docs/auth-cookie-model.md)
- **Containerization**: Docker + Docker Compose — dev (`docker-compose.yml`:
  `app`, `worker`, `beat`, `db`, `redis`) and production
  (`docker-compose.prod.yml`: adds `nginx` for TLS; see
  [`docs/deployment.md`](docs/deployment.md))
- **Testing**: pytest, against a real Postgres database (not SQLite/mocks);
  mocked HTTP transports (`httpx.MockTransport`) for scanner-module tests
  instead of live external websites; Vitest + Testing Library + MSW on
  the frontend

## Running it (development)

```bash
cp .env.example .env        # then edit secrets, especially JWT_SECRET_KEY
docker compose up -d db redis
docker compose run --rm app alembic upgrade head
docker compose up -d app worker
```

This also creates the `asm_test` database automatically (via
`docker/postgres/init-test-db.sql`, mounted into Postgres's
`docker-entrypoint-initdb.d`) — but only on a **fresh** volume. If you
have an existing dev volume from before this was added, create it once
manually:
```bash
docker compose exec db psql -U asm -d asm -c "CREATE DATABASE asm_test;"
```

API docs (Swagger UI): http://localhost:8000/docs
OpenAPI schema: http://localhost:8000/openapi.json
Health check: http://localhost:8000/health

For the frontend dev server:
```bash
cd frontend
npm ci
npm run dev
```

## Running it (production)

See [`docs/deployment.md`](docs/deployment.md) for the full walkthrough
(frontend build, self-signed TLS cert, running
`docker-compose.prod.yml`). Short version:
```bash
cd frontend && npm ci && npm run build && cd ..
docker\nginx\generate-self-signed-cert.ps1
docker compose -p asm-prod -f docker-compose.prod.yml up -d --build
docker exec asm-prod-app-1 alembic -c alembic.ini upgrade head   # first run only
```

### Authentication (cookie-based — see docs/auth-cookie-model.md)

Tokens are delivered as `httpOnly` cookies, never in the response body —
`curl`'s cookie jar (`-c`/`-b`) stands in for what a browser does
automatically. State-changing requests also need the CSRF token echoed
back in a header:

```bash
# Register (bootstraps an org + admin user) — sets cookies, returns the user
curl -X POST http://localhost:8000/auth/register -H "Content-Type: application/json" \
  -d '{"organization_name": "Acme Corp", "email": "admin@example.com", "password": "a-long-passphrase", "full_name": "Ada Admin"}' \
  -c cookies.txt

CSRF=$(grep csrf_token cookies.txt | awk '{print $NF}')
```

Every example below reuses `-b cookies.txt -c cookies.txt` (send *and*
update the jar) and `-H "X-CSRF-Token: $CSRF"` on any `POST`/`PATCH`.

### Running a scan end to end

```bash
# 1. Create an asset
curl -X POST http://localhost:8000/assets -b cookies.txt -c cookies.txt \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"asset_type": "domain", "value": "example.com"}'
# -> {"id": "<asset_id>", ...}

# 2. Confirm you're authorized to scan it — required before any scan will run
curl -X POST http://localhost:8000/assets/<asset_id>/confirm-authorization \
  -b cookies.txt -c cookies.txt -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"authorization_confirmed": true}'

# 3. Queue a scan (runs async — requires `worker` to be up)
curl -X POST http://localhost:8000/scans -b cookies.txt -c cookies.txt \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"asset_id": "<asset_id>", "modules": ["dns", "ssl", "technology", "security_headers"]}'
# -> {"id": "<scan_id>", "status": "queued", "findings": [], ...}

# 4. Poll until it's done
curl http://localhost:8000/scans/<scan_id> -b cookies.txt
```

**Port scanning** (the one active module) requires an `ip_address` asset
and must be named explicitly — it's never included when `modules` is
omitted:

```bash
curl -X POST http://localhost:8000/scans -b cookies.txt -c cookies.txt \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"asset_id": "<ip_address_asset_id>", "modules": ["port_scanner"]}'
```

### Scheduling recurring discovery (Step 9.11)

Requires `worker` **and** `beat` both running (`docker compose up -d
worker beat`) — `beat` dispatches due schedules every 60s, `worker`
executes them.

```bash
# 1. Create + authorize a seed asset (same as scanning — see above)

# 2. Create a schedule: re-run the "dns" provider against this asset
#    every 6 hours, starting now
curl -X POST http://localhost:8000/discovery/schedules -b cookies.txt -c cookies.txt \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"seed_asset_id": "<asset_id>", "provider_name": "dns", "interval_hours": 6}'
# -> {"id": "<schedule_id>", "enabled": true, "next_run_at": "...", ...}

# 3. (optional) trigger it immediately instead of waiting for the next
#    tick — this enqueues, it does not execute inline
curl -X POST http://localhost:8000/discovery/schedules/<schedule_id>/run \
  -b cookies.txt -c cookies.txt -H "X-CSRF-Token: $CSRF"
# -> {"id": "<run_id>", "status": "queued", ...}

# 4. Poll the run the same way as any other discovery run
curl http://localhost:8000/discovery/runs/<run_id> -b cookies.txt

# 5. Disable a schedule (e.g. before revoking authorization on its asset)
curl -X PATCH http://localhost:8000/discovery/schedules/<schedule_id> \
  -b cookies.txt -c cookies.txt -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

If authorization on the seed asset is ever revoked while a schedule is
still enabled, the next scheduled execution fails closed and the
schedule auto-disables itself (`disabled_reason` explains why) rather
than continuing to fire against an unauthorized target.

### Reviewing and acting on alerts (Step 9.12)

Alerts are generated automatically by discovery (manual or scheduled)
— nothing to trigger explicitly. To review and act on them:

```bash
# List open, high-priority alerts first
curl "http://localhost:8000/alerts?status=open&priority=high&priority=critical" -b cookies.txt

# Filter to one asset's alerts
curl "http://localhost:8000/alerts?asset_id=<asset_id>" -b cookies.txt

# Read one alert's full detail, including its evidence
curl http://localhost:8000/alerts/<alert_id> -b cookies.txt

# Acknowledge it (admin/analyst only)
curl -X POST http://localhost:8000/alerts/<alert_id>/acknowledge \
  -b cookies.txt -c cookies.txt -H "X-CSRF-Token: $CSRF"

# Resolve it once addressed (acknowledging first is optional)
curl -X POST http://localhost:8000/alerts/<alert_id>/resolve \
  -b cookies.txt -c cookies.txt -H "X-CSRF-Token: $CSRF"
```

Email notifications are off by default (`ALERT_NOTIFICATION_EMAIL_ENABLED=false`).
To enable them, set `ALERT_NOTIFICATION_EMAIL_ENABLED=true` plus
`SMTP_HOST`/`SMTP_PORT`/`SMTP_USERNAME`/`SMTP_PASSWORD`/
`SMTP_FROM_ADDRESS` in `.env` and restart `worker` — every active
`admin` in the alert's organization is emailed once per newly created
alert (never per repeated/deduplicated occurrence).

### Generating a report

```bash
curl -X POST http://localhost:8000/reports -b cookies.txt -c cookies.txt \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"scan_id": "<scan_id>", "format": "pdf"}'
# -> {"id": "<report_id>", "status": "completed", ...}

curl http://localhost:8000/reports/<report_id>/download -b cookies.txt -o report.pdf
```

`format` is one of `json`, `csv`, `pdf`. Report generation is synchronous
(fast enough not to need a queue) but fully decoupled from the API layer —
see `app/services/report_service.py` and `app/reporting/`.

### Admin: users and audit logs

```bash
# Change a user's role or active status (admin-only, same org only,
# cannot target your own account)
curl -X PATCH http://localhost:8000/users/<user_id> -b cookies.txt -c cookies.txt \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"is_active": false}'

# Read the org's audit trail (admin-only), optionally filtered
curl "http://localhost:8000/audit-logs?action=scan.execute&limit=50" -b cookies.txt
```

### Running tests

Backend:
```bash
docker compose up -d db redis        # all the ordinary suite needs
docker compose run --rm app pytest
```

The suite is fail-safe by construction — `tests/isolation.py`, applied at
the top of `tests/conftest.py` before any app module is imported:

- **Environment**: the suite only runs with `ENVIRONMENT` set to
  `development` or `test` — an allowlist, so `production`, `prod`,
  `staging` or anything unexpected refuses to start.
- **Database**: `TEST_DATABASE_URL` is required (there is no fallback to
  `DATABASE_URL`) and must name a dedicated database following the strict
  `<name>_test` convention (e.g. `asm_test`). If it names the same
  database as `DATABASE_URL` the suite refuses, whatever the hostnames —
  different hostnames, IPs or ports can reach the same server. On top of
  those rules, the database it actually reaches must carry an explicit
  marker set at provisioning time: fresh volumes get it from
  `docker/postgres/init-test-db.sql`; mark a pre-existing test database
  once with
  `docker compose exec db psql -U asm -d asm_test -c "COMMENT ON DATABASE asm_test IS 'asm-disposable-test-database';"`.
  The whole test process — including executors that open their own
  sessions — is pointed at that database, and every TRUNCATE/DROP
  re-checks it first.
- **Redis**: tests use their own Redis DB — `REDIS_URL`'s server with DB
  index 15, or `TEST_REDIS_URL` if set — whose index must differ from
  `REDIS_URL`'s regardless of host (hostnames can alias one server; a
  different index is a different database). Running tests next to a
  running stack can't flush or feed the live broker.
- **Network**: real DNS resolution, DNS traffic, and connections beyond
  loopback test servers and the test Redis are blocked for the whole
  session, and any test that attempts them fails — an ordinary run
  performs no real discovery or scanning. New tests must mock the network
  boundary.
- **Test-only provider**: the suite enables the `stub` discovery provider
  for itself (`ENABLE_TEST_DISCOVERY_PROVIDERS`); it stays unavailable
  everywhere else.

The one live-stack test (`tests/test_celery_integration.py`) is opt-in: it
registers an organization in the **development** database and has the
live worker run a real DNS scan.

```bash
docker compose up -d db redis app worker
docker compose run --rm -e ASM_RUN_LIVE_STACK_TESTS=1 app pytest tests/test_celery_integration.py
```

Frontend:
```bash
cd frontend
npm ci
npm test          # vitest run
npm run typecheck  # tsc --noEmit
npm run build      # production build
```

See "Latest full test run" at the end of this README for the current
pass/fail counts.

## Project layout

```
asm/
├── docker-compose.yml            # dev: app, worker, beat (Step 9.11), db, redis
├── docker-compose.prod.yml       # prod: adds nginx (TLS), no --reload/bind-mounts
├── docker/
│   ├── backend/Dockerfile
│   ├── nginx/                    # nginx.conf, self-signed cert generator
│   └── postgres/init-test-db.sql # auto-creates asm_test on a fresh volume
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, CORS, CSRF middleware, rate-limit wiring, /health
│   │   ├── config.py             # env-driven settings
│   │   ├── celery_app.py         # Celery app + config
│   │   ├── database.py           # SQLAlchemy engine/session
│   │   ├── security.py           # password hashing, JWT (access + jti-bearing refresh), CSRF token generation
│   │   ├── dependencies.py       # get_current_user (cookie-based), require_role
│   │   ├── core/
│   │   │   ├── cookies.py         # cookie names + set/clear helpers (single source of truth for flags)
│   │   │   ├── csrf_middleware.py # double-submit CSRF enforcement, applied globally
│   │   │   ├── client_ip.py       # trusted-proxy-aware client IP resolution (rate limiting, audit logs)
│   │   │   └── validation.py      # target validation (rejects private/link-local/reserved IPs too)
│   │   ├── models/                # SQLAlchemy models (21 tables, incl. AssetRelationship/Observation — Step 8, DiscoveryRun/DiscoveryResult — Step 9.1, DiscoverySchedule — Step 9.11, Alert/AlertNotification — Step 9.12)
│   │   ├── schemas/                # Pydantic request/response models, incl. graph.py (Step 9.8), risk.py (Step 9.10), discovery_schedule.py (Step 9.11), alert.py (Step 9.12)
│   │   ├── api/routes/             # auth, users, assets(+graph/activity/summary/shared-infrastructure — Step 9.8, +prioritized/{id}/risk — Step 9.10), scans, reports, audit_logs, discovery(+schedules — Step 9.11), alerts (Step 9.12)
│   │   ├── scanners/                # ScannerModule ABC + 6 modules (incl. port_scanner) + net_safety/http_client(public fetch_url, Step 9.5)/pinned_transport + registry
│   │   ├── discovery/               # DiscoveryProvider ABC + registry + stub_provider (9.1), dns_provider (9.2), certificate_provider (9.3), subdomain_provider (9.4), http_provider (9.5), network_provider (9.6), cloud_provider + cloud_classification (9.7)
│   │   ├── services/
│   │   │   ├── scan_service.py     # sync validate/create/queue/cancel (atomic transitions)
│   │   │   ├── scan_executor.py    # async execution, fail-closed re-check before EACH module
│   │   │   ├── refresh_token_service.py  # issue/rotate/revoke, reuse detection
│   │   │   ├── account_lockout.py  # Redis-backed brute-force protection (Step 7A)
│   │   │   ├── rate_limit.py       # slowapi Limiter, fail-closed
│   │   │   ├── asset_relationship_service.py, observation_service.py  # the Asset Graph (Step 8)
│   │   │   ├── discovery_service.py, discovery_normalization_service.py  # discovery orchestration + Step-8-service reuse (Step 9.1)
│   │   │   ├── graph_service.py    # read-only graph traversal/activity-feed(+pagination, 9.9)/summary queries over existing data (Step 9.8)
│   │   │   ├── prioritization_service.py  # explainable, on-demand asset priority -- no persistence, no network I/O (Step 9.10)
│   │   │   ├── discovery_schedule_service.py  # schedule CRUD + validation (request-facing, Step 9.11)
│   │   │   ├── discovery_scheduler_executor.py  # claim/dispatch/execute + reap-stale-runs (worker-facing, Step 9.11)
│   │   │   ├── alert_service.py    # rule engine + dedup/fingerprinting + lifecycle (Step 9.12)
│   │   │   ├── alert_notification_service.py  # email rendering + smtplib send (Step 9.12)
│   │   │   ├── alert_delivery_executor.py  # worker-facing delivery claim/retry (Step 9.12)
│   │   │   ├── risk_engine.py, report_service.py, audit_service.py
│   │   ├── reporting/              # builder + json/csv/pdf renderers
│   │   └── tasks/                  # Celery task wrappers, incl. discovery_schedule_tasks.py (9.11), alert_notification_tasks.py (9.12)
│   ├── alembic/                    # migrations 0001 (Phase 1) .. 0014 (Step 9.12, alerts) — Steps 9.8, 9.9, and 9.10 added no migration
│   └── tests/
├── frontend/
│   └── src/
│       ├── pages/                  # Dashboard, Assets(+Detail), Scans(+Detail), Findings, Reports, Settings, Login, Register
│       ├── auth/                   # AuthProvider, RequireAuth guard
│       ├── api/, hooks/, components/, lib/
│       └── types/api.generated.ts  # generated from the live OpenAPI schema
└── docs/
    ├── risk-scoring.md
    ├── auth-cookie-model.md
    └── deployment.md
```

## Roadmap: Step 8 onward

With the foundation (Steps 1-7) tagged, subsequent work follows this
sequence — not reordered, each gated on the prior step actually being
closed:

Step 8 Asset Intelligence → 9 Passive Discovery → 10 Active Discovery →
11 Technology Fingerprinting → 12 Exposure Detection → 13 Finding
Intelligence → 14 Risk Engine → 15 Asset Criticality → 16 Continuous
Monitoring → 17 Change Detection → 18 Attack Surface Graph → 19 Analyst
Workflow → 20 Advanced Reporting → 21 Alerting → 22 Multi-Tenant
Hardening → 23 API/Integrations → 24 CI/CD Integration → 25 Production
Operations → 26 Scale Testing → 27 Full Security Assessment →
28 Documentation + Release → **v1.0**.

Every step is scoped against the product-capability statement at the top
of this README, not feature novelty.

## Release readiness (Step 7C)

Before tagging a foundation milestone, this audit answers one question:
if this repository were cloned onto another machine and the
documentation above followed literally, would you get the system this
README describes — without hidden credentials, dev settings, accidental
exposure, or undocumented manual steps? It's re-run (against an actual
fresh `git clone`, not the working tree) before each foundation tag.

Checks: clean-clone reproducibility, fresh migrations, dev and prod
compose startup, `.env.example` completeness, secret handling, auth/RBAC/
cross-org isolation/scan-authorization/report-access/audit-log test
coverage, nginx/TLS, database/Redis exposure, Docker image contents,
frontend production build, both test suites, git hygiene, documentation
accuracy, and a dependency/security scan.

## Known, disclosed debt (not silently shipped, not yet addressed)

- `ssl_module.py` (Phase 1) used to connect via a direct socket without
  the pre-resolution IP validation `net_safety`/`pinned_transport`
  provide elsewhere — **resolved**: every connection it makes now goes
  through `net_safety.resolve_and_validate` first (allowed ports only;
  every resolved address checked against the private/loopback/
  link-local/reserved/multicast rules) and is pinned to a validated IP
  with the real hostname still sent as SNI, including the second,
  deprecated-TLS probe connection. Covered by `tests/test_ssl_module.py`
  (the module previously had no dedicated tests).
- The port scanner intentionally does not support `ip_range` assets yet
  (single-host only) — see `port_scanner_module.py`'s docstring.
- Rate limiting is uniform per-route (e.g. all of `/scans` creation
  shares one limit), not conditionally stricter specifically for
  `port_scanner` requests — see `rate_limit_scan_create` in
  `app/config.py`.
- No user-facing "log out of all other sessions" endpoint (the
  underlying revocation-of-all-tokens exists and is exercised by reuse
  detection, just not exposed as a deliberate action).
- No password-change/password-reset flow exists at all.
- User email uniqueness is global, not per-organization — enables
  account enumeration via registration. Deliberately deferred out of
  Step 7A's scope.
- The production Docker image installs `requirements-dev.txt` (pytest,
  pytest-cov) — same image serves dev/test and prod. A real fix needs a
  multi-stage Dockerfile with separate build targets; flagged during
  Step 7C, not yet done.
- Backend/frontend dependencies are broadly behind latest; `react-router`
  specifically has two named moderate CVEs (open-redirect via
  `<Link>`/`useNavigate`; an SSR-hydration constructor-injection issue
  that's likely inapplicable since this app has no SSR). No dependency
  upgrades have been made without a concrete cause, to avoid churn
  unrelated to the security work actually in scope.
- `AssetType.service`/`tls_certificate` are reserved enum values, not
  creatable via `POST /assets` (still 422s) — **resolved, not deferred,
  as of Step 9.1**: `Service`/`Certificate` stay child-detail tables,
  reachable via `Asset.services`/`Asset.certificates`, never
  `AssetRelationship` endpoints. Nothing realistic needs a service or
  certificate to be its own graph node — "example.com has a service on
  port 443" is fully expressible as an attribute of the `example.com`
  asset. That would only matter for a relationship *between* two
  services (e.g. "these hosts share a fingerprint") — a plausible future
  need, but not one any provider through Step 9.2 requires, so making
  the schema change now would be speculative. No migration was made for
  this reason.
- `AssetType.web3_*`/`rpc_endpoint` are reserved the same way — no Web3
  implementation exists yet, by explicit instruction for this pass.
- No write endpoints for `Asset.owner`/`tags` yet — currently settable
  only via direct DB access, readable via `GET /assets`.
  (`environment`/`criticality` are writable via `PATCH /assets/{id}`
  since Stage A.1.)
- `Observation` only records what this pass's own code paths produce
  (asset/relationship creation and removal) — no generic field-level
  diffing (IP changed, DNS changed, port opened/closed, ...) exists yet;
  that needs real discovery/re-scanning logic (Step 9+) to have anything
  to diff against.
- `Observation` is asset-scoped only, not relationship-scoped (e.g. a
  relationship's confidence changing isn't recorded as its own
  observation yet) — a non-breaking future addition (a nullable
  `relationship_id` FK), not something the current schema forecloses.
- `dns`, `certificate`, `subdomain`, `http`, `network`, and `cloud` are
  real providers now (Steps 9.2-9.7) — repository enrichment and Web3
  are still unimplemented, by design (each is its own later step).
- Discovery runs execute synchronously (no Celery task) — fine for the
  DNS/certificate/subdomain providers' bounded operations so far, but a
  slower future provider may need the async wiring this deliberately
  still defers. Wiring it (mirroring `scan_tasks.py`) is a small,
  additive change, not built speculatively ahead of a provider that
  actually needs it.
- No cancellation for an in-flight discovery run (moot while execution
  is synchronous) and no enforced timeout at the orchestration layer
  (the DNS/certificate providers each enforce their own 5s connection
  timeout internally; nothing yet enforces a timeout on a provider as a
  whole).
- The `certificate` provider only accepts `domain`/`subdomain` seeds —
  `ip_address`/`url` seeds are excluded, since SAN-scope validation
  doesn't have a clean meaning for a bare IP. Flagged as deferred, not
  silently dropped.
- Certificate-derived SAN candidates don't yet have their own dedicated
  `RelationshipType` — `related_to` (the existing generic type) is
  reused rather than inventing one for "these hostnames share a TLS
  certificate," per this batch's explicit instruction not to add
  relationship types without a clear semantic gap.
- A `DiscoveryRun` takes exactly one `seed_asset_id` — multi-seed runs
  would need a non-breaking future join table, not a redesign.
- Every discovery-driven asset refresh writes an `Observation`, even
  when nothing but `last_seen` changed — fine at today's scale, a
  candidate for de-duplication once a real provider runs on a schedule
  and produces meaningfully more volume.
- **`belongs_to` direction bug: found in Step 9.2, fixed in Step 9.4.**
  `discovery_normalization_service` used to always make the *seed* the
  relationship source; `belongs_to` semantically wants the *discovered*
  thing as source ("a subdomain belongs_to its domain," not the
  reverse). Fixed once a real provider (subdomain discovery) needed the
  correct direction — `_REVERSED_DIRECTION_RELATIONSHIP_TYPES` now
  reverses it automatically, centralized in the normalization layer, no
  provider-side awareness needed. The only prior user was the Step 9.1
  stub fixture, so the fix was contained and safe; regression-covered
  for both the corrected direction and the general rule.
- The `subdomain` provider only queries Certificate Transparency — no
  second (DNS-based) discovery source yet, deliberately (see the Step
  9.4 section above). No true pagination against crt.sh — bounded
  processing caps instead (`_MAX_RAW_ENTRIES`/`_MAX_CANDIDATE_HOSTNAMES`,
  documented in the provider).
- Unicode/IDNA hostnames from CT data are safely rejected, not
  converted — building real IDNA→punycode handling is a distinct,
  separate feature, not added speculatively here.
- The `http` provider's redirect authorization-scope check only
  inspects the *final* response URL, not every intermediate hop — a
  chain that transits out of scope and back in would not be specially
  flagged. Matches the spec's own one-hop example; a stricter per-hop
  scope check is a reasonable future hardening, not built speculatively
  here.
- The `http` provider always uses `GET` (streamed, size-capped), never
  `HEAD` — `HEAD` can't yield a page title, and adding a
  HEAD-then-GET-fallback would exceed the "1 request per scheme"
  budget. `GET`'s existing streaming+cap behavior in `http_client.py`
  keeps this cheap in practice.
- Technology inference (`http` provider) covers `Server`/`X-Powered-By`
  headers and one HTML generator-meta-tag marker only — intentionally
  not the fuller signature set `technology_module.py` uses for active
  scans, per this batch's explicit "no giant technology database"
  instruction. Expanding it later is additive, not a redesign.
- **`network` provider's reverse-DNS (PTR) handling is conservative by
  necessity, not by inference quality**: every PTR hostname is evidence
  only, never a candidate Asset, because `is_hostname_in_scope` has no
  honest meaning for a bare-IP seed (see the Step 9.6 README section
  above) — a real fix needs either an organization-level authorized-
  hostname-pattern concept or DB access inside providers, neither of
  which exists yet. Flagged as a found architectural gap, not silently
  worked around.
- CGNAT / Shared Address Space (`100.64.0.0/10`, RFC 6598) used to pass
  `app.core.validation.validate_ip_address`/`validate_ip_range` and
  `net_safety._is_blocked_ip`, since Python's `ipaddress` module sets
  neither `is_private` nor `is_reserved` for it — **resolved**: both now
  block it explicitly from one shared definition
  (`app.core.validation.SHARED_ADDRESS_SPACE`). It isn't globally
  routable, so it can never be an externally visible asset, and some
  cloud platforms serve internal endpoints from it (Alibaba Cloud's
  instance metadata service is `100.100.100.200`). Applies to asset
  creation, discovery candidates, and every outbound consumer — HTTP
  discovery and the HTTP-based scanner modules, certificate discovery,
  SSL scanning, port scanning, and the network provider's seed check —
  covered by `tests/test_ssrf_address_policy.py`.
- The `network` provider makes two DNS queries per successful ASN
  lookup (origin, then AS-name) plus one independent PTR query — Team
  Cymru's own service is split into two lookups by design (the origin
  response doesn't carry the AS's registered name), so this isn't an
  unbounded per-candidate loop, but it is more than one request.
- Announced prefix/organization/country/registry are `network` provider
  evidence only, never their own Asset — see the Step 9.6 README
  section above for the full reasoning (avoids reopening the
  over-broad-CIDR risk `max_ip_range_prefix_length` exists to prevent).
- **`cloud` provider has no provider-published IP range list** (AWS's
  `ip-ranges.json` and equivalents) — deliberately deferred, see the
  Step 9.7 README section above. This caps achievable confidence below
  "certain" even for a well-corroborated multi-signal match; a real fix
  is a separate subsystem (fetch/cache/refresh those lists), not a
  quick addition.
- `cloud` provider's known-primary-ASN table
  (`app/discovery/cloud_classification.py::_KNOWN_PROVIDER_ASNS`) is
  small and intentionally incomplete — each listed provider operates
  many more ASNs in reality than the handful recorded here. An
  unrecognized ASN simply falls through to the (still useful, lower-
  weighted) organization-name signal rather than asserting a false
  negative, but the table itself is not exhaustive and will drift as
  providers acquire/renumber ASNs over time.
- `cloud` provider's HTTP-server/TLS-issuer signature patterns
  (`_PROVIDER_SIGNATURES` in the same file) cover a conservative subset
  of well-known providers and well-known patterns — a provider not
  listed there (or a listed provider using an unmatched header/issuer
  format) classifies as `unknown` rather than misattributed, which is
  the intended fail-safe behavior, but means real coverage gaps exist
  and will grow as infrastructure patterns change.
- Correlation across assets (`get_shared_infrastructure_groups`) —
  **resolved in Step 9.8**: now exposed via `GET /assets/shared-infrastructure`,
  closing the gap disclosed at the end of Step 9.7.
- `cloud` provider's HTTP/TLS evidence correlation takes the *first*
  related hostname (via `resolves_to`) that has each kind of evidence,
  rather than merging or flagging disagreement if multiple hostnames
  resolving to the same IP show different Server headers or certificate
  issuers — a real but narrow edge case (e.g. shared hosting/virtual
  IPs), not built out in this pass.
- `GET /assets/activity`'s cross-asset `Observation` query has no
  dedicated index — it joins through `Asset` for org-scoping (Observation
  itself carries no `organization_id`) and relies on the existing
  `(asset_id, observed_at)` index plus the join. Fine at today's scale;
  if `EXPLAIN` or real usage later shows this needs its own index, that
  should be reported and added deliberately, not assumed now — per
  explicit instruction, no index was added speculatively in this pass.
- `GET /assets/{id}/graph`'s BFS issues one query per depth level
  (batched via `IN()`), not a single recursive-CTE query — a deliberate
  choice for correctness/testability/determinism over raw query count,
  reasonable at this codebase's stated per-organization scale; revisit
  only if profiling on a much larger graph shows it matters.
- `/assets/activity`, `/assets/summary`, `/assets/shared-infrastructure`
  are static routes that must stay registered *before* `/assets/{asset_id}`
  in `assets.py` — any future single-segment static route under `/assets`
  added after that line would be silently swallowed by the path-param
  route instead of matching. Documented inline in the router; no
  structural guard against it beyond that comment and this note.
- `GET /assets/summary` computes every statistic on demand (no caching/
  materialization) — reasonable at current per-organization scale;
  would need revisiting only if an organization's asset count grew
  large enough for the `GROUP BY` queries to become slow, which hasn't
  been observed.
- **Disappearance detection cannot distinguish a genuine partial
  disappearance from a genuine partial provider hiccup** — see the Step
  9.9 section above for the full, explicit statement of what the
  zero-candidates safety guard does and doesn't catch. Solving this
  fully needs every provider to report per-sub-check success/failure,
  not just an overall run outcome — a real, larger change, not made
  here.
- Disappearance detection's asset-level cascade
  (`_maybe_mark_asset_disappeared`) checks for *any* other active
  relationship before marking an asset disappeared, but does not
  distinguish *which* provider or seed that other relationship came
  from — an asset kept "alive" by a single stale-but-not-yet-detected
  relationship from an unrelated, long-dead seed would still be
  protected from disappearing. Acceptable at this stage (erring toward
  not destructively marking things disappeared, per explicit
  instruction); a more precise cascade is future work.
- `canonicalize_for_comparison` sorts list-of-dicts by their own JSON
  representation — correct and deterministic, but means two evidence
  entries differing only in float precision (e.g. `0.7` vs `0.70`)
  would sort differently even though `0.7 == 0.7` in the underlying
  comparison; not a real concern for anything this codebase currently
  stores (JSON round-trips Python floats consistently), but noted as a
  theoretical edge case, not verified against exhaustively.
- **`tags` is not a scoring input** — no established vocabulary exists
  yet for what a tag *means* (there's no write endpoint for it at all —
  a pre-existing, still-open gap from Step 8.1/9.5), so nothing is
  inferred from one in Step 9.10's model. Once a real tag taxonomy
  exists, this is a natural, additive extension point.
- `prioritization_service`'s connectivity signal only looks at direct
  (1-hop) relationships and a flat "connects to a high/critical
  neighbor" check — no multi-hop attack-surface relevance, no
  betweenness/bridge detection. Deliberately conservative per explicit
  instruction ("do not claim an actual exploit path merely because two
  assets are connected"); a genuinely more sophisticated graph-relevance
  model is future work, not attempted here.
- `GET /assets/prioritized` computes priority for every asset matching
  the SQL-level filters before sorting/limiting in Python (the ranking
  itself isn't a DB column to `ORDER BY`/`OFFSET` on) — reasonable at
  this codebase's stated per-organization scale (proven non-N+1, but
  still bounded by total matching-asset count, not the page size). True
  keyset pagination over a computed ranking is a harder problem than
  paginating a stored column; not built speculatively here.
- Change-recency's window (`RECENT_CHANGE_WINDOW = 24h`) is a single,
  global constant — not configurable per organization or per asset
  type. Reasonable as a first cut; a real per-org tuning need would be
  the concrete signal to make it configurable later.

## Latest full test run

```
docker compose run --rm app pytest
================= 930 passed, 1 skipped, 0 failed =================

cd frontend && npx vitest run
================= 48 test files, 294 tests passed =================

cd frontend && npm run build
================= tsc --noEmit && vite build -- succeeds =================
```

The one skip is the opt-in live-stack test (`tests/test_celery_integration.py`,
see "Running tests"); with `ASM_RUN_LIVE_STACK_TESTS=1` it runs too. The
backend count includes `tests/test_discovery_scheduler_concurrency.py`'s four genuine-Postgres
discovery-schedule concurrency tests, and
`tests/test_alert_concurrency.py`'s two genuine-Postgres alert-dedup
concurrency tests (real threads, real database sessions, no mocking of
either claim/dedup mechanism itself).

Frontend count grew from 230 (39 files) to 285 (47 files) in Step 9.13 —
8 new page/component test files (`OverviewPage`, `AssetsPage` rewritten,
`AssetDetailPage` extended, `ChangeTimelinePage`, `AlertsPage`,
`PrioritizedAssetsPage`, `MonitoringPage`, `GraphView`, `AppShell`,
`routes` composition), plus updates to every existing test whose fixture
shape changed when `types/api.generated.ts` was regenerated against the
now much larger live OpenAPI schema. Stage A.1 added 9 more (285 to 294,
one new file, `hooks/useUpdateAsset.test.tsx`).
