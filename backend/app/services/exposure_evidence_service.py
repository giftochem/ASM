"""Observed external-exposure evidence (Stage A.2) -- the entry-point
foundation for attack-path analysis. Answers one question per asset:
"has a real, attributable observation shown a service reachable from
outside, and how recently?" It never infers exploitability or current
availability, never makes a network request, and never writes anything.

What counts (and what doesn't), from how each source actually stores
its results:

- HTTP: the `http` provider records one DiscoveryResult per scheme per
  run -- `observed`/`refreshed`/`unchanged` with a `status_code` when
  the endpoint responded, `failed` for a network-level failure,
  `rejected` when a redirect left the authorized scope. An unchanged
  re-confirmation writes NO Observation (only the DiscoveryResult), so
  results, not Observations, are the confirmation history. Any status
  code -- 403, 404 and 500 included -- means the endpoint responded.
- TLS: the `certificate` provider records a result only after a
  completed handshake; a failed handshake fails the whole run instead.
  The ssl scan module stores SSLInfo only on a successful handshake.
  A Certificate row on its own is inventory -- it can't say where it
  came from or whether the service still answers -- so it never
  qualifies by itself.
- Ports: the port_scanner module records every scanned port's state for
  completed, authorization-checked scans.
- DNS records, certificate-transparency names and asset type are
  context, never service exposure.

Only results from the real providers/modules named below can qualify --
a test-only or unknown provider (e.g. `stub`) never does, whatever its
results say. Observations alone record no provider, so an HTTP
Observation with no attributable result never qualifies either.

Every attempt is one of three things:

- confirmed: the service answered (a status code, a handshake, an open
  port).
- negative: a definitive observation that contradicts exposure. The only
  structured one stored today is a port scan's `closed` state (the
  connection was actively refused).
- inconclusive: everything else that failed. The http and certificate
  providers and the scan modules store failures only as free text
  (`failure_reason`, `error_message`, a Finding description), so a DNS
  failure, a timeout and a refused connection can't be told apart
  without guessing from message wording -- which this module never
  does. A `filtered` port (timeout or unreachable) and an HTTP redirect
  out of scope (a response was received but deliberately not recorded)
  are inconclusive too. Inconclusive attempts stay visible but never
  invalidate a confirmation.

Freshness, from the latest confirmation (`current` is not a claim that
the service is up right now -- only that it was observed recently and
nothing since contradicts it):

- current: confirmed within FRESHNESS_WINDOW of `as_of`, with no
  negative at or after that confirmation.
- stale: confirmed, but longer ago than the window.
- superseded: a negative at or after the latest confirmation (a tie
  goes against the confirmation).
- unknown: no confirmation time is recorded.

Only `current` evidence qualifies as an observed entry point. Evaluation
is point-in-time: records after `as_of` are ignored, and every choice
between records uses a total ordering, so the same data and `as_of`
always give the same answer whatever order rows come back in.
"""

import enum
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.enums import ChangeType, DiscoveryResultOutcome, DiscoveryRunStatus, LifecycleStatus, ScanStatus
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.discovery_result import DiscoveryResult
from app.models.discovery_run import DiscoveryRun
from app.models.observation import Observation
from app.models.port_scan_result import PortScanResult
from app.models.scan import Scan
from app.models.ssl_info import SSLInfo
from app.services.prioritization_service import INHERENTLY_EXPOSED_TYPES

# v0.1's window. A plain module constant like prioritization's
# RECENT_CHANGE_WINDOW; callers (Stage B) can pass their own.
FRESHNESS_WINDOW = timedelta(days=7)

# The only sources that can establish service exposure. An allowlist, so
# a test-only or future provider never qualifies by accident.
HTTP_PROVIDER = "http"
CERTIFICATE_PROVIDER = "certificate"
PORT_SCANNER_MODULE = "port_scanner"
SSL_MODULE = "ssl"
EVIDENCE_PROVIDERS = frozenset({HTTP_PROVIDER, CERTIFICATE_PROVIDER})

_HTTP_CONFIRMING_OUTCOMES = {
    DiscoveryResultOutcome.observed,
    DiscoveryResultOutcome.refreshed,
    DiscoveryResultOutcome.unchanged,
}
_TLS_CONFIRMING_OUTCOMES = {
    DiscoveryResultOutcome.created,
    DiscoveryResultOutcome.refreshed,
    DiscoveryResultOutcome.unchanged,
}

_FREE_TEXT_FAILURE = "its failure is stored only as free text, so a DNS failure, a timeout and a refused connection look the same"


class EvidenceType(str, enum.Enum):
    http_response = "http_response"
    tls_handshake = "tls_handshake"
    open_port = "open_port"
    # Context only -- never qualifies.
    certificate_record = "certificate_record"
    dns_records = "dns_records"
    certificate_transparency = "certificate_transparency"


SERVICE_EVIDENCE_TYPES = frozenset({EvidenceType.http_response, EvidenceType.tls_handshake, EvidenceType.open_port})
_TYPE_ORDER = {evidence_type: index for index, evidence_type in enumerate(EvidenceType)}


class Freshness(str, enum.Enum):
    current = "current"
    stale = "stale"
    superseded = "superseded"
    unknown = "unknown"


class AttemptResult(str, enum.Enum):
    confirmed = "confirmed"
    negative = "negative"
    inconclusive = "inconclusive"


# Tie-break among same-time attempts: a negative counts as the latest.
_RESULT_RANK = {AttemptResult.confirmed: 0, AttemptResult.inconclusive: 1, AttemptResult.negative: 2}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class ExposureEvidence:
    asset_id: uuid.UUID
    evidence_type: EvidenceType
    source: str  # e.g. "discovery:http", "scan:port_scanner"
    subject: str  # what was observed: "https", "example.com:443", "443/tcp"
    freshness: Freshness
    qualifies: bool  # an observed entry point on its own
    first_confirmed_at: datetime | None = None
    last_confirmed_at: datetime | None = None
    latest_attempt_at: datetime | None = None
    contradicted_at: datetime | None = None  # the negative that superseded it, if any
    inconclusive_attempts: int = 0  # at or after the latest confirmation
    latest_inconclusive_at: datetime | None = None
    discovery_run_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None
    result_id: uuid.UUID | None = None  # DiscoveryResult / PortScanResult / SSLInfo of the latest confirmation
    observation_id: uuid.UUID | None = None
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssetExposure:
    asset_id: uuid.UUID
    asset_type: str
    is_observed_entry_point: bool
    evidence: tuple[ExposureEvidence, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class _Attempt:
    at: datetime | None
    result: AttemptResult
    note: str = ""  # what a non-confirming attempt was, for limitations
    result_id: uuid.UUID | None = None
    discovery_run_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None


def _order_key(attempt: _Attempt):
    """A total order: time, then rank (so a same-time negative sorts
    last), then ids -- never insertion order."""
    return (
        attempt.at is not None,
        attempt.at or _EPOCH,
        _RESULT_RANK[attempt.result],
        str(attempt.result_id or ""),
        str(attempt.discovery_run_id or ""),
        str(attempt.scan_id or ""),
    )


@dataclass
class _Slot:
    """Everything known about one observable thing (an HTTP scheme, a TLS
    host:port, a port) on one asset."""

    asset_id: uuid.UUID
    evidence_type: EvidenceType
    source: str
    subject: str
    attempts: list[_Attempt] = field(default_factory=list)
    observation_id: uuid.UUID | None = None


def assess_exposure(
    db: Session,
    organization_id: uuid.UUID,
    asset_ids=None,
    *,
    as_of: datetime | None = None,
    freshness_window: timedelta = FRESHNESS_WINDOW,
) -> dict[uuid.UUID, AssetExposure]:
    """Exposure evidence for the organization's assets (all of them, or
    those of `asset_ids` that belong to it -- another organization's ids
    are simply absent from the result). A fixed number of queries
    however many assets are assessed."""
    as_of = as_of or datetime.now(timezone.utc)
    query = db.query(Asset).filter(Asset.organization_id == organization_id)
    if asset_ids is not None:
        asset_ids = list(asset_ids)
        if not asset_ids:
            return {}
        query = query.filter(Asset.id.in_(asset_ids))
    assets = {asset.id: asset for asset in query.all()}
    if not assets:
        return {}

    ids = list(assets)
    observations = _observations_by_asset(db, ids, as_of)
    slots: list[_Slot] = []
    slots += _discovery_slots(db, organization_id, ids, as_of, observations)
    slots += _scan_slots(db, ids, as_of)

    evidence: dict[uuid.UUID, list[ExposureEvidence]] = defaultdict(list)
    for slot in slots:
        # Only something that was actually confirmed becomes evidence --
        # failures alone never produce an item.
        if any(attempt.result is AttemptResult.confirmed for attempt in slot.attempts):
            evidence[slot.asset_id].append(_slot_evidence(slot, as_of, freshness_window))
    _add_unattributed_http(evidence, observations, as_of, freshness_window)
    _add_certificate_records(db, ids, evidence)
    _add_context_evidence(evidence, observations, as_of, freshness_window)

    return {
        asset_id: _assess_asset(asset, evidence.get(asset_id, []))
        for asset_id, asset in sorted(assets.items(), key=lambda item: str(item[0]))
    }


def assess_asset_exposure(
    db: Session,
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    *,
    as_of: datetime | None = None,
    freshness_window: timedelta = FRESHNESS_WINDOW,
) -> AssetExposure | None:
    """One asset; None when it doesn't exist in this organization."""
    return assess_exposure(
        db, organization_id, [asset_id], as_of=as_of, freshness_window=freshness_window
    ).get(asset_id)


# --- collection ---------------------------------------------------------------------


def _observations_by_asset(db: Session, ids: list, as_of: datetime) -> dict[uuid.UUID, list[Observation]]:
    rows = (
        db.query(Observation)
        .filter(
            Observation.asset_id.in_(ids),
            Observation.observed_at <= as_of,
            Observation.change_type.in_(
                [
                    ChangeType.http_observed,
                    ChangeType.http_changed,
                    ChangeType.certificate_observed,
                    ChangeType.certificate_changed,
                    ChangeType.dns_records_observed,
                    ChangeType.certificate_transparency_observed,
                ]
            ),
        )
        .all()
    )
    by_asset: dict[uuid.UUID, list[Observation]] = defaultdict(list)
    for row in sorted(rows, key=lambda r: (r.observed_at, str(r.id)), reverse=True):
        by_asset[row.asset_id].append(row)  # newest first, ties by id
    return by_asset


def _latest_observation(observations: list[Observation], change_types: tuple, field_name: str) -> Observation | None:
    for observation in observations:  # newest first
        if observation.change_type in change_types and observation.field_name == field_name:
            return observation
    return None


def _http_attempt(result: DiscoveryResult, run: DiscoveryRun) -> _Attempt:
    evidence = result.evidence or {}
    common = {"at": result.created_at, "result_id": result.id, "discovery_run_id": run.id}
    if result.outcome in _HTTP_CONFIRMING_OUTCOMES and isinstance(evidence.get("status_code"), int):
        return _Attempt(result=AttemptResult.confirmed, **common)
    if result.outcome is DiscoveryResultOutcome.rejected:
        note = "the response redirected outside the authorized scope, so it wasn't recorded as evidence"
    elif result.outcome is DiscoveryResultOutcome.failed:
        note = f"the HTTP attempt failed; {_FREE_TEXT_FAILURE}"
    else:
        note = "the result recorded no status code"
    return _Attempt(result=AttemptResult.inconclusive, note=note, **common)


def _discovery_slots(db: Session, organization_id, ids: list, as_of: datetime, observations) -> list[_Slot]:
    runs = {
        run.id: run
        for run in db.query(DiscoveryRun).filter(
            DiscoveryRun.organization_id == organization_id,
            DiscoveryRun.seed_asset_id.in_(ids),
            DiscoveryRun.provider_name.in_(sorted(EVIDENCE_PROVIDERS)),
            DiscoveryRun.status.in_([DiscoveryRunStatus.completed, DiscoveryRunStatus.failed]),
        )
    }
    if not runs:
        return []

    slots: dict[tuple, _Slot] = {}
    failed_runs: dict[tuple, list[_Attempt]] = defaultdict(list)  # (asset, provider) -> whole-run failures
    for run in runs.values():
        if run.status is DiscoveryRunStatus.failed and (run.completed_at is None or run.completed_at <= as_of):
            failed_runs[(run.seed_asset_id, run.provider_name)].append(
                _Attempt(
                    at=run.completed_at,
                    result=AttemptResult.inconclusive,
                    note=f"the {run.provider_name} discovery run failed; {_FREE_TEXT_FAILURE}",
                    discovery_run_id=run.id,
                )
            )

    results = (
        db.query(DiscoveryResult)
        .filter(DiscoveryResult.discovery_run_id.in_(list(runs)), DiscoveryResult.created_at <= as_of)
        .all()
    )
    for result in results:
        run = runs[result.discovery_run_id]
        # A result about anything but the run's own seed isn't this
        # evidence (http/certificate results always name the seed).
        if run.status is not DiscoveryRunStatus.completed or result.resulting_asset_id != run.seed_asset_id:
            continue
        if run.provider_name == HTTP_PROVIDER:
            scheme = (result.evidence or {}).get("scheme")
            if scheme not in ("http", "https"):
                continue
            key = (run.seed_asset_id, EvidenceType.http_response, scheme)
            source = f"discovery:{HTTP_PROVIDER}"
            attempt = _http_attempt(result, run)
        elif run.provider_name == CERTIFICATE_PROVIDER:
            if result.outcome not in _TLS_CONFIRMING_OUTCOMES:
                continue
            key = (run.seed_asset_id, EvidenceType.tls_handshake, result.candidate_value)
            source = f"discovery:{CERTIFICATE_PROVIDER}"
            attempt = _Attempt(
                at=result.created_at, result=AttemptResult.confirmed, result_id=result.id, discovery_run_id=run.id
            )
        else:
            continue
        slot = slots.setdefault(key, _Slot(asset_id=key[0], evidence_type=key[1], source=source, subject=key[2]))
        slot.attempts.append(attempt)

    for (asset_id, evidence_type, subject), slot in slots.items():
        provider = HTTP_PROVIDER if evidence_type is EvidenceType.http_response else CERTIFICATE_PROVIDER
        slot.attempts.extend(failed_runs.get((asset_id, provider), []))
        if evidence_type is EvidenceType.http_response:
            observation = _latest_observation(
                observations.get(asset_id, []), (ChangeType.http_observed, ChangeType.http_changed), f"http:{subject}"
            )
        else:
            observation = _latest_observation(
                observations.get(asset_id, []), (ChangeType.certificate_observed, ChangeType.certificate_changed), subject
            )
        slot.observation_id = observation.id if observation is not None else None
    return list(slots.values())


def _port_attempt(row: PortScanResult, scan: Scan) -> _Attempt:
    common = {"at": scan.completed_at, "result_id": row.id, "scan_id": scan.id}
    if row.state == "open":
        return _Attempt(result=AttemptResult.confirmed, **common)
    if row.state == "closed":
        return _Attempt(result=AttemptResult.negative, note="the port was closed (the connection was refused)", **common)
    if row.state == "filtered":
        return _Attempt(
            result=AttemptResult.inconclusive, note="the port was filtered (the probe timed out or the host was unreachable)", **common
        )
    return _Attempt(result=AttemptResult.inconclusive, note=f"unrecognized port state '{row.state}'", **common)


def _scan_slots(db: Session, ids: list, as_of: datetime) -> list[_Slot]:
    # A completed scan has already passed the scan executor's
    # authorization re-check; queued/running/failed/cancelled scans prove
    # nothing.
    scans = {
        scan.id: scan
        for scan in db.query(Scan).filter(Scan.asset_id.in_(ids), Scan.status == ScanStatus.completed)
        if scan.completed_at is None or scan.completed_at <= as_of
    }
    if not scans:
        return []

    slots: dict[tuple, _Slot] = {}
    scans_with_rows: dict[str, set] = {PORT_SCANNER_MODULE: set(), SSL_MODULE: set()}
    for row in db.query(PortScanResult).filter(PortScanResult.scan_id.in_(list(scans))):
        scan = scans[row.scan_id]
        if row.asset_id != scan.asset_id:
            continue
        scans_with_rows[PORT_SCANNER_MODULE].add(scan.id)
        subject = f"{row.port}/{row.protocol}"
        key = (scan.asset_id, EvidenceType.open_port, subject)
        slot = slots.setdefault(
            key, _Slot(asset_id=scan.asset_id, evidence_type=EvidenceType.open_port, source=f"scan:{PORT_SCANNER_MODULE}", subject=subject)
        )
        slot.attempts.append(_port_attempt(row, scan))
    for row in db.query(SSLInfo).filter(SSLInfo.scan_id.in_(list(scans))):
        scan = scans[row.scan_id]
        if row.asset_id != scan.asset_id:
            continue
        scans_with_rows[SSL_MODULE].add(scan.id)
        subject = f"{row.hostname}:{row.port}"
        key = (scan.asset_id, EvidenceType.tls_handshake, subject, SSL_MODULE)
        slot = slots.setdefault(
            key, _Slot(asset_id=scan.asset_id, evidence_type=EvidenceType.tls_handshake, source=f"scan:{SSL_MODULE}", subject=subject)
        )
        slot.attempts.append(
            _Attempt(at=scan.completed_at, result=AttemptResult.confirmed, result_id=row.id, scan_id=scan.id)
        )

    # A completed scan that ran a module but stored nothing for it means
    # the module couldn't complete (blocked target, DNS failure, failed
    # handshake) -- stored only as a free-text Finding, so inconclusive
    # for everything that module had seen on that asset.
    for scan in scans.values():
        for module in (PORT_SCANNER_MODULE, SSL_MODULE):
            if module in (scan.modules_requested or []) and scan.id not in scans_with_rows[module]:
                for slot in slots.values():
                    if slot.asset_id == scan.asset_id and slot.source == f"scan:{module}":
                        slot.attempts.append(
                            _Attempt(
                                at=scan.completed_at,
                                result=AttemptResult.inconclusive,
                                note=f"the {module} scan module stored no result; {_FREE_TEXT_FAILURE}",
                                scan_id=scan.id,
                            )
                        )
    return list(slots.values())


# --- classification -----------------------------------------------------------------


@dataclass(frozen=True)
class _Classification:
    freshness: Freshness
    first: _Attempt | None
    last: _Attempt | None
    latest_attempt_at: datetime | None
    contradicted_at: datetime | None
    inconclusive_attempts: int
    latest_inconclusive_at: datetime | None
    limitations: tuple[str, ...]


def _classify(attempts: list[_Attempt], as_of: datetime, window: timedelta) -> _Classification:
    ordered = sorted(attempts, key=_order_key)
    timed = [a for a in ordered if a.at is not None]
    confirmations = [a for a in timed if a.result is AttemptResult.confirmed]
    latest_attempt_at = timed[-1].at if timed else None
    limitations: list[str] = []
    untimed = [a for a in ordered if a.at is None and a.result is not AttemptResult.confirmed]
    if untimed:
        limitations.append(f"{len(untimed)} failed attempt(s) have no recorded time, so they couldn't be ordered and weren't used")
    if not confirmations:
        return _Classification(
            Freshness.unknown, None, None, latest_attempt_at, None, 0, None,
            ("no confirmation time is recorded, so freshness is unknown", *limitations),
        )

    first, last = confirmations[0], confirmations[-1]
    # At or after the latest confirmation; a same-time negative counts
    # against it (the conservative reading of a tie).
    since = [a for a in timed if a.at >= last.at and a.result is not AttemptResult.confirmed]
    negatives = [a for a in since if a.result is AttemptResult.negative]
    inconclusive = [a for a in since if a.result is AttemptResult.inconclusive]

    if inconclusive:
        latest = inconclusive[-1]
        limitations.append(
            f"{len(inconclusive)} inconclusive attempt(s) since the last confirmation neither confirmed nor "
            f"contradicted it (latest {latest.at.isoformat()}: {latest.note})"
        )
    contradicted_at = negatives[-1].at if negatives else None
    if negatives:
        freshness = Freshness.superseded
        limitations.insert(0, f"contradicted at {negatives[-1].at.isoformat()}: {negatives[-1].note}")
    elif as_of - last.at <= window:
        freshness = Freshness.current
    else:
        freshness = Freshness.stale
        limitations.insert(0, f"last confirmed {last.at.isoformat()}, more than {window} before the assessment time")
    return _Classification(
        freshness,
        first,
        last,
        latest_attempt_at,
        contradicted_at,
        len(inconclusive),
        inconclusive[-1].at if inconclusive else None,
        tuple(limitations),
    )


def _slot_evidence(slot: _Slot, as_of: datetime, window: timedelta) -> ExposureEvidence:
    c = _classify(slot.attempts, as_of, window)
    # Identify the latest confirmation; without a timed one, the
    # deterministic last untimed one.
    anchor = c.last or sorted((a for a in slot.attempts if a.result is AttemptResult.confirmed), key=_order_key)[-1]
    return ExposureEvidence(
        asset_id=slot.asset_id,
        evidence_type=slot.evidence_type,
        source=slot.source,
        subject=slot.subject,
        freshness=c.freshness,
        qualifies=c.freshness is Freshness.current,
        first_confirmed_at=c.first.at if c.first else None,
        last_confirmed_at=c.last.at if c.last else None,
        latest_attempt_at=c.latest_attempt_at,
        contradicted_at=c.contradicted_at,
        inconclusive_attempts=c.inconclusive_attempts,
        latest_inconclusive_at=c.latest_inconclusive_at,
        discovery_run_id=anchor.discovery_run_id,
        scan_id=anchor.scan_id,
        result_id=anchor.result_id,
        observation_id=slot.observation_id,
        limitations=c.limitations,
    )


def _single_observation_classification(observation: Observation, as_of: datetime, window: timedelta) -> _Classification:
    return _classify([_Attempt(at=observation.observed_at, result=AttemptResult.confirmed)], as_of, window)


def _add_unattributed_http(evidence, observations, as_of: datetime, window: timedelta) -> None:
    """HTTP Observations record no provider. Where no attributable
    result backs them, they're reported but never qualify."""
    for asset_id, rows in observations.items():
        attributed = {e.subject for e in evidence.get(asset_id, []) if e.evidence_type is EvidenceType.http_response}
        for scheme in ("http", "https"):
            if scheme in attributed:
                continue
            observation = _latest_observation(rows, (ChangeType.http_observed, ChangeType.http_changed), f"http:{scheme}")
            if observation is None:
                continue
            c = _single_observation_classification(observation, as_of, window)
            evidence[asset_id].append(
                ExposureEvidence(
                    asset_id=asset_id,
                    evidence_type=EvidenceType.http_response,
                    source="observation",
                    subject=scheme,
                    freshness=c.freshness,
                    qualifies=False,
                    last_confirmed_at=c.last.at if c.last else None,
                    observation_id=observation.id,
                    limitations=c.limitations + ("no attributable provider result backs this observation",),
                )
            )


def _add_certificate_records(db: Session, ids: list, evidence) -> None:
    handshake_subjects = {
        (e.asset_id, e.subject) for items in evidence.values() for e in items if e.evidence_type is EvidenceType.tls_handshake
    }
    for certificate in db.query(Certificate).filter(Certificate.asset_id.in_(ids)):
        subject = f"{certificate.hostname}:{certificate.port}"
        if (certificate.asset_id, subject) in handshake_subjects:
            continue
        evidence[certificate.asset_id].append(
            ExposureEvidence(
                asset_id=certificate.asset_id,
                evidence_type=EvidenceType.certificate_record,
                source="certificate_inventory",
                subject=subject,
                freshness=Freshness.unknown,
                qualifies=False,
                limitations=(
                    "a certificate record alone does not prove a currently reachable service",
                    "no attributable TLS handshake result backs this record",
                ),
            )
        )


def _add_context_evidence(evidence, observations, as_of: datetime, window: timedelta) -> None:
    context = (
        (ChangeType.dns_records_observed, EvidenceType.dns_records, "DNS records show name resolution only, not a reachable service"),
        (
            ChangeType.certificate_transparency_observed,
            EvidenceType.certificate_transparency,
            "certificate-transparency entries are issuance history, not a reachable service",
        ),
    )
    for asset_id, rows in observations.items():
        for change_type, evidence_type, reason in context:
            observation = next((row for row in rows if row.change_type is change_type), None)
            if observation is None:
                continue
            c = _single_observation_classification(observation, as_of, window)
            evidence[asset_id].append(
                ExposureEvidence(
                    asset_id=asset_id,
                    evidence_type=evidence_type,
                    source=f"observation:{change_type.value}",
                    subject=observation.field_name or "",
                    freshness=c.freshness,
                    qualifies=False,
                    last_confirmed_at=c.last.at if c.last else None,
                    observation_id=observation.id,
                    limitations=(reason,) + c.limitations,
                )
            )


def _assess_asset(asset: Asset, items: list[ExposureEvidence]) -> AssetExposure:
    limitations: list[str] = []
    inactive_reason = None
    if not asset.is_active:
        inactive_reason = "the asset is deactivated"
    elif asset.status is LifecycleStatus.disappeared:
        inactive_reason = "the asset is marked disappeared"
    if inactive_reason is not None:
        limitations.append(f"{inactive_reason}; none of its evidence qualifies")
        items = [
            replace(e, qualifies=False, limitations=e.limitations + (inactive_reason,)) if e.qualifies else e
            for e in items
        ]

    items = sorted(items, key=lambda e: (_TYPE_ORDER[e.evidence_type], e.subject, e.source))
    is_entry_point = any(e.qualifies for e in items)
    if not is_entry_point:
        if not any(e.evidence_type in SERVICE_EVIDENCE_TYPES for e in items):
            limitations.append("no HTTP response, TLS handshake or open port has been observed")
        else:
            limitations.append("no service observation is both attributable and current")
        if asset.asset_type in INHERENTLY_EXPOSED_TYPES:
            limitations.append(f"asset type '{asset.asset_type.value}' alone does not establish exposure")
    return AssetExposure(
        asset_id=asset.id,
        asset_type=asset.asset_type.value,
        is_observed_entry_point=is_entry_point,
        evidence=tuple(items),
        limitations=tuple(limitations),
    )
