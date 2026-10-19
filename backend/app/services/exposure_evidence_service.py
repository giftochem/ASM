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

Bounded retrieval: attempt history is never loaded wholesale. Per slot,
the database returns one row each for the latest confirmation, the
earliest confirmation and the latest negative (DISTINCT ON / GROUP BY)
-- everything qualification depends on -- plus inconclusive attempts
inside the freshness window only, newest first, at most
INCONCLUSIVE_PER_ASSET per asset. All of it draws on one per-assessment
EVIDENCE_ROW_BUDGET, qualification-critical queries first. A cut is
always detected (one row past the budget is fetched) and handled
conservatively: evidence that couldn't be fully checked is never treated
as current, and the asset is flagged `evidence_truncated`. Inconclusive
attempts are counted within the window, so for evidence last confirmed
before it the count covers the window only (said on the evidence).
"""

import enum
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

from sqlalchemy import String, and_, case, cast, exists, func, literal, null, or_, select, tuple_, union_all
from sqlalchemy.dialects.postgresql import UUID as PGUUID
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
    # True when the evidence budget cut something qualification depends
    # on for this asset: it may be missing evidence, and anything that
    # couldn't be fully checked was not treated as current.
    evidence_truncated: bool = False


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

    ids = sorted(assets, key=str)
    window_start = as_of - freshness_window
    budget = _Budget(EVIDENCE_ROW_BUDGET)
    loaded = _load_slots(db, organization_id, ids, as_of, window_start, budget)
    observations, observations_cut = _observations_by_asset(db, ids, as_of, budget)
    _attach_observations(loaded.slots, observations)

    evidence: dict[uuid.UUID, list[ExposureEvidence]] = defaultdict(list)
    for slot in loaded.slots.values():
        # Only something that was actually confirmed becomes evidence --
        # failures alone never produce an item. (Every loaded slot has a
        # confirmation: slots come from the latest-confirmation query.)
        item = _slot_evidence(slot, as_of, freshness_window)
        evidence[slot.asset_id].append(_apply_retrieval_limits(item, slot, loaded, window_start))
    _add_unattributed_http(evidence, observations, as_of, freshness_window)
    certificates_cut = _add_certificate_records(db, ids, evidence, budget)
    _add_context_evidence(evidence, observations, as_of, freshness_window)

    notes = defaultdict(list)
    for asset_id in _affected(ids, observations_cut):
        notes[asset_id].append("the evidence budget was reached before every observation was loaded")
    for asset_id in _affected(ids, certificates_cut):
        notes[asset_id].append("the evidence budget was reached before every certificate record was loaded")
    return {
        asset_id: _assess_asset(
            assets[asset_id], evidence.get(asset_id, []), asset_id in loaded.truncated_assets, notes.get(asset_id, [])
        )
        for asset_id in ids
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


# --- bounded retrieval ----------------------------------------------------------------

# Rows loaded into Python per assessment, across every evidence query.
# Qualification-critical queries (latest confirmations, latest negatives)
# draw on it first.
EVIDENCE_ROW_BUDGET = 20_000
# Newest inconclusive attempts in the freshness window examined per asset
# (they only feed counts -- they never change qualification).
INCONCLUSIVE_PER_ASSET = 25

_SOURCE_HTTP = f"discovery:{HTTP_PROVIDER}"
_SOURCE_TLS = f"discovery:{CERTIFICATE_PROVIDER}"
_SOURCE_PORTS = f"scan:{PORT_SCANNER_MODULE}"
_SOURCE_SSL = f"scan:{SSL_MODULE}"
_SOURCE_TYPES = {
    _SOURCE_HTTP: EvidenceType.http_response,
    _SOURCE_TLS: EvidenceType.tls_handshake,
    _SOURCE_PORTS: EvidenceType.open_port,
    _SOURCE_SSL: EvidenceType.tls_handshake,
}
_NOTES = {
    "http_failed": f"the HTTP attempt failed; {_FREE_TEXT_FAILURE}",
    "http_rejected": "the response redirected outside the authorized scope, so it wasn't recorded as evidence",
    "http_no_status": "the result recorded no status code",
    f"run_failed_{HTTP_PROVIDER}": f"the {HTTP_PROVIDER} discovery run failed; {_FREE_TEXT_FAILURE}",
    f"run_failed_{CERTIFICATE_PROVIDER}": f"the {CERTIFICATE_PROVIDER} discovery run failed; {_FREE_TEXT_FAILURE}",
    "port_closed": "the port was closed (the connection was refused)",
    "port_filtered": "the port was filtered (the probe timed out or the host was unreachable)",
    f"module_empty_{PORT_SCANNER_MODULE}": f"the {PORT_SCANNER_MODULE} scan module stored no result; {_FREE_TEXT_FAILURE}",
    f"module_empty_{SSL_MODULE}": f"the {SSL_MODULE} scan module stored no result; {_FREE_TEXT_FAILURE}",
}
_UUID = PGUUID(as_uuid=True)


class _Budget:
    """Rows still allowed this assessment. Each query fetches one row past
    what's left, so a cut is always detected, never silent. Statements
    must be ordered by asset id first: then a cut leaves every asset
    before the first dropped row complete."""

    def __init__(self, rows: int):
        self.remaining = rows

    def _keep(self, rows: list, asset_of) -> tuple[list, uuid.UUID | None]:
        if len(rows) <= self.remaining:
            self.remaining -= len(rows)
            return rows, None
        cut_at = asset_of(rows[self.remaining])
        kept = rows[: self.remaining]
        self.remaining = 0
        return kept, cut_at

    def rows(self, db: Session, statement) -> tuple[list, uuid.UUID | None]:
        return self._keep(db.execute(statement.limit(self.remaining + 1)).all(), lambda row: row.asset_id)

    def entities(self, db: Session, query) -> tuple[list, uuid.UUID | None]:
        return self._keep(query.limit(self.remaining + 1).all(), lambda entity: entity.asset_id)


def _affected(ids: list, cut_at: uuid.UUID | None) -> set[uuid.UUID]:
    """Assets a cut may have touched: the one whose row was dropped and
    every asset after it (UUID order, as Postgres sorts them)."""
    return {asset_id for asset_id in ids if cut_at is not None and asset_id >= cut_at}


def _attempt_rows(organization_id, ids: list, as_of: datetime):
    """Every evidence attempt for these assets up to `as_of`, as one
    UNION ALL of uniform rows: (asset_id, source, subject, kind, note, ts,
    result_id, discovery_run_id, scan_id). `subject` is NULL for
    asset-level attempts -- a whole failed run, or a scan module that
    stored nothing -- which apply to every slot of that source. Nothing
    here is executed on its own; callers filter, collapse and bound it."""
    run, result, scan = DiscoveryRun, DiscoveryResult, Scan
    no_uuid, no_text = cast(null(), _UUID), cast(null(), String)
    untimed_or_by = lambda column: or_(column <= as_of, column.is_(None))  # noqa: E731

    scheme = result.evidence["scheme"].astext
    status_code = result.evidence["status_code"]
    responded = and_(
        result.outcome.in_(sorted(_HTTP_CONFIRMING_OUTCOMES, key=str)),
        func.jsonb_typeof(status_code) == "number",
        status_code.astext.op("~")("^[0-9]+$"),
    )
    http = (
        select(
            run.seed_asset_id.label("asset_id"),
            literal(_SOURCE_HTTP, String).label("source"),
            scheme.label("subject"),
            case((responded, "confirmed"), else_="inconclusive").label("kind"),
            case(
                (responded, ""),
                (result.outcome == DiscoveryResultOutcome.rejected, "http_rejected"),
                (result.outcome == DiscoveryResultOutcome.failed, "http_failed"),
                else_="http_no_status",
            ).label("note"),
            result.created_at.label("ts"),
            result.id.label("result_id"),
            run.id.label("discovery_run_id"),
            no_uuid.label("scan_id"),
        )
        .select_from(result)
        .join(run, run.id == result.discovery_run_id)
        .where(
            run.organization_id == organization_id,
            run.seed_asset_id.in_(ids),
            run.provider_name == HTTP_PROVIDER,
            run.status == DiscoveryRunStatus.completed,
            result.resulting_asset_id == run.seed_asset_id,
            scheme.in_(("http", "https")),
            result.created_at <= as_of,
        )
    )
    tls = (
        select(
            run.seed_asset_id, literal(_SOURCE_TLS, String), result.candidate_value, literal("confirmed", String),
            literal("", String), result.created_at, result.id, run.id, no_uuid,
        )
        .select_from(result)
        .join(run, run.id == result.discovery_run_id)
        .where(
            run.organization_id == organization_id,
            run.seed_asset_id.in_(ids),
            run.provider_name == CERTIFICATE_PROVIDER,
            run.status == DiscoveryRunStatus.completed,
            result.resulting_asset_id == run.seed_asset_id,
            result.outcome.in_(sorted(_TLS_CONFIRMING_OUTCOMES, key=str)),
            result.created_at <= as_of,
        )
    )
    failed_runs = select(
        run.seed_asset_id, func.concat("discovery:", run.provider_name), no_text, literal("inconclusive", String),
        func.concat("run_failed_", run.provider_name), run.completed_at, no_uuid, run.id, no_uuid,
    ).where(
        run.organization_id == organization_id,
        run.seed_asset_id.in_(ids),
        run.provider_name.in_(sorted(EVIDENCE_PROVIDERS)),
        run.status == DiscoveryRunStatus.failed,
        untimed_or_by(run.completed_at),
    )
    # A completed scan has already passed the scan executor's
    # authorization re-check; queued/running/failed/cancelled scans prove
    # nothing.
    completed_scan = and_(scan.asset_id.in_(ids), scan.status == ScanStatus.completed, untimed_or_by(scan.completed_at))
    port = PortScanResult
    ports = (
        select(
            scan.asset_id, literal(_SOURCE_PORTS, String), func.concat(port.port, "/", port.protocol),
            case((port.state == "open", "confirmed"), (port.state == "closed", "negative"), else_="inconclusive"),
            case(
                (port.state == "open", ""),
                (port.state == "closed", "port_closed"),
                (port.state == "filtered", "port_filtered"),
                else_=func.concat("port_other:", port.state),
            ),
            scan.completed_at, port.id, no_uuid, scan.id,
        )
        .select_from(port)
        .join(scan, scan.id == port.scan_id)
        .where(completed_scan, port.asset_id == scan.asset_id)
    )
    ssl = (
        select(
            scan.asset_id, literal(_SOURCE_SSL, String), func.concat(SSLInfo.hostname, ":", SSLInfo.port),
            literal("confirmed", String), literal("", String), scan.completed_at, SSLInfo.id, no_uuid, scan.id,
        )
        .select_from(SSLInfo)
        .join(scan, scan.id == SSLInfo.scan_id)
        .where(completed_scan, SSLInfo.asset_id == scan.asset_id)
    )

    def module_stored_nothing(module: str, rows_model, source: str):
        # A completed scan that ran a module but stored nothing for it:
        # the module couldn't complete (blocked target, DNS failure,
        # failed handshake), recorded only as a free-text Finding.
        stored = exists().where(rows_model.scan_id == scan.id, rows_model.asset_id == scan.asset_id)
        return select(
            scan.asset_id, literal(source, String), no_text, literal("inconclusive", String),
            literal(f"module_empty_{module}", String), scan.completed_at, no_uuid, no_uuid, scan.id,
        ).where(completed_scan, scan.modules_requested.any(module), ~stored)

    return union_all(
        http, tls, failed_runs, ports, ssl,
        module_stored_nothing(PORT_SCANNER_MODULE, PortScanResult, _SOURCE_PORTS),
        module_stored_nothing(SSL_MODULE, SSLInfo, _SOURCE_SSL),
    ).subquery("evidence_attempts")


def _newest_first(columns):
    """SQL counterpart of _order_key, descending: time (untimed last),
    then ids -- the same choice _classify makes among equal-rank rows."""
    return (
        columns.ts.desc().nulls_last(),
        columns.result_id.desc().nulls_last(),
        columns.discovery_run_id.desc().nulls_last(),
        columns.scan_id.desc().nulls_last(),
    )


@dataclass
class _LoadedSlots:
    slots: dict[tuple, _Slot]
    truncated_assets: set[uuid.UUID]  # something qualification depends on was cut
    unverified_negatives: set[uuid.UUID]  # port slots whose later results weren't all checked
    first_unknown: set[uuid.UUID]
    inconclusive_capped: set[uuid.UUID]  # more inconclusive attempts in the window than were examined
    inconclusive_unloaded: set[uuid.UUID]  # window attempts not examined at all (budget)


def _attempt(row) -> _Attempt:
    note = row.note or ""
    if note.startswith("port_other:"):
        text = f"unrecognized port state '{note.removeprefix('port_other:')}'"
    else:
        text = _NOTES.get(note, "")
    return _Attempt(
        at=row.ts,
        result=AttemptResult(row.kind),
        note=text,
        result_id=row.result_id,
        discovery_run_id=row.discovery_run_id,
        scan_id=row.scan_id,
    )


def _load_slots(db: Session, organization_id, ids: list, as_of: datetime, window_start: datetime, budget: _Budget) -> _LoadedSlots:
    attempts = _attempt_rows(organization_id, ids, as_of)
    c = attempts.c
    key = (c.asset_id, c.source, c.subject)

    # 1. Latest confirmation per slot (qualification-critical). Slots
    #    exist only where something was confirmed.
    latest, latest_cut = budget.rows(
        db, select(attempts).where(c.kind == "confirmed").distinct(*key).order_by(*key, *_newest_first(c))
    )
    slots: dict[tuple, _Slot] = {}
    for row in latest:
        slot = _Slot(asset_id=row.asset_id, evidence_type=_SOURCE_TYPES[row.source], source=row.source, subject=row.subject)
        slot.attempts.append(_attempt(row))
        slots[(row.asset_id, row.source, row.subject)] = slot
    truncated = _affected(ids, latest_cut)

    # 2. Latest negative per confirmed port slot (qualification-critical:
    #    a negative at or after the confirmation supersedes it).
    unverified: set[uuid.UUID] = set()
    port_slots = sorted({(asset_id, subject) for asset_id, source, subject in slots if source == _SOURCE_PORTS}, key=str)
    if port_slots:
        negatives, negatives_cut = budget.rows(
            db,
            select(attempts)
            .where(c.kind == "negative", c.source == _SOURCE_PORTS, tuple_(c.asset_id, c.subject).in_(port_slots))
            .distinct(*key)
            .order_by(*key, *_newest_first(c)),
        )
        for row in negatives:
            slots[(row.asset_id, row.source, row.subject)].attempts.append(_attempt(row))
        unverified = _affected(ids, negatives_cut)
        truncated |= unverified

    # 3. Earliest timed confirmation per slot (reporting only).
    earliest, earliest_cut = budget.rows(
        db,
        select(c.asset_id, c.source, c.subject, func.min(c.ts).label("ts"))
        .where(c.kind == "confirmed", c.ts.isnot(None))
        .group_by(*key)
        .order_by(*key),
    )
    for row in earliest:
        slot = slots.get((row.asset_id, row.source, row.subject))
        if slot is not None:
            slot.attempts.append(_Attempt(at=row.ts, result=AttemptResult.confirmed))

    # 4. Inconclusive attempts inside the freshness window, newest first,
    #    at most INCONCLUSIVE_PER_ASSET per asset (counts only).
    capped: set[uuid.UUID] = set()
    unloaded: set[uuid.UUID] = set()
    slot_assets = sorted({asset_id for asset_id, _, _ in slots}, key=str)
    if slot_assets:
        numbered = (
            select(attempts, func.row_number().over(partition_by=c.asset_id, order_by=_newest_first(c)).label("rn"))
            .where(
                c.kind == "inconclusive",
                c.asset_id.in_(slot_assets),
                or_(and_(c.ts >= window_start, c.ts <= as_of), c.ts.is_(None)),
            )
            .subquery("window_inconclusive")
        )
        inconclusive, inconclusive_cut = budget.rows(
            db,
            select(numbered).where(numbered.c.rn <= INCONCLUSIVE_PER_ASSET + 1).order_by(numbered.c.asset_id, numbered.c.rn),
        )
        for row in inconclusive:
            if row.rn > INCONCLUSIVE_PER_ASSET:
                capped.add(row.asset_id)  # the extra row only proves there are more
                continue
            if row.subject is None:  # asset-level: every slot of that source
                targets = [s for (asset_id, source, _), s in slots.items() if asset_id == row.asset_id and source == row.source]
            else:
                targets = [slots[k] for k in [(row.asset_id, row.source, row.subject)] if k in slots]
            for slot in targets:
                slot.attempts.append(_attempt(row))
        unloaded = _affected(slot_assets, inconclusive_cut)

    return _LoadedSlots(
        slots=slots,
        truncated_assets=truncated,
        unverified_negatives=unverified,
        first_unknown=_affected(ids, earliest_cut),
        inconclusive_capped=capped,
        inconclusive_unloaded=unloaded,
    )


def _observations_by_asset(
    db: Session, ids: list, as_of: datetime, budget: _Budget
) -> tuple[dict[uuid.UUID, list[Observation]], uuid.UUID | None]:
    """Only the latest observation per (asset, change type, field) -- all
    any caller uses -- collapsed in the database."""
    query = (
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
        .distinct(Observation.asset_id, Observation.change_type, Observation.field_name)
        .order_by(
            Observation.asset_id,
            Observation.change_type,
            Observation.field_name,
            Observation.observed_at.desc(),
            Observation.id.desc(),
        )
    )
    rows, cut_at = budget.entities(db, query)
    by_asset: dict[uuid.UUID, list[Observation]] = defaultdict(list)
    for row in sorted(rows, key=lambda r: (r.observed_at, str(r.id)), reverse=True):
        by_asset[row.asset_id].append(row)  # newest first, ties by id
    return by_asset, cut_at


def _latest_observation(observations: list[Observation], change_types: tuple, field_name: str) -> Observation | None:
    for observation in observations:  # newest first
        if observation.change_type in change_types and observation.field_name == field_name:
            return observation
    return None


def _attach_observations(slots: dict[tuple, _Slot], observations) -> None:
    for (asset_id, source, subject), slot in slots.items():
        if source == _SOURCE_HTTP:
            change_types, field_name = (ChangeType.http_observed, ChangeType.http_changed), f"http:{subject}"
        elif source == _SOURCE_TLS:
            change_types, field_name = (ChangeType.certificate_observed, ChangeType.certificate_changed), subject
        else:
            continue
        observation = _latest_observation(observations.get(asset_id, []), change_types, field_name)
        slot.observation_id = observation.id if observation is not None else None


def _apply_retrieval_limits(item: ExposureEvidence, slot: _Slot, loaded: _LoadedSlots, window_start: datetime) -> ExposureEvidence:
    """Says what bounded retrieval left out of this item, and never lets
    an item that couldn't be fully checked count as current."""
    limitations = list(item.limitations)
    if slot.source == _SOURCE_PORTS and slot.asset_id in loaded.unverified_negatives:
        limitations.insert(0, "the evidence budget was reached before this port's later results were checked, so it isn't treated as current")
        item = replace(item, freshness=Freshness.unknown, qualifies=False, contradicted_at=None)
    if slot.asset_id in loaded.first_unknown:
        limitations.append("the earliest confirmation wasn't determined (evidence budget reached)")
        item = replace(item, first_confirmed_at=None)
    if slot.asset_id in loaded.inconclusive_unloaded:
        limitations.append("inconclusive attempts weren't examined (evidence budget reached)")
    elif slot.asset_id in loaded.inconclusive_capped:
        limitations.append(
            f"only the newest {INCONCLUSIVE_PER_ASSET} inconclusive attempts in the freshness window were examined; "
            f"the count is a lower bound"
        )
    if item.last_confirmed_at is not None and item.last_confirmed_at < window_start:
        limitations.append("inconclusive attempts are counted within the freshness window only")
    return replace(item, limitations=tuple(limitations))


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


def _add_certificate_records(db: Session, ids: list, evidence, budget: _Budget) -> uuid.UUID | None:
    handshake_subjects = {
        (e.asset_id, e.subject) for items in evidence.values() for e in items if e.evidence_type is EvidenceType.tls_handshake
    }
    certificates, cut_at = budget.entities(
        db,
        db.query(Certificate)
        .filter(Certificate.asset_id.in_(ids))
        .order_by(Certificate.asset_id, Certificate.hostname, Certificate.port, Certificate.id),
    )
    for certificate in certificates:
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
    return cut_at


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


def _assess_asset(
    asset: Asset, items: list[ExposureEvidence], evidence_truncated: bool = False, notes: list[str] | None = None
) -> AssetExposure:
    limitations: list[str] = []
    if evidence_truncated:
        limitations.append(
            "the evidence budget was reached before this asset's evidence was fully examined: it may be missing "
            "evidence, and nothing that couldn't be fully checked is treated as current"
        )
    limitations.extend(notes or ())
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
        evidence_truncated=evidence_truncated,
    )
