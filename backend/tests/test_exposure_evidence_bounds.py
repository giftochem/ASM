"""Stage B correction: bounded evidence retrieval in
exposure_evidence_service. History length and density must not change
what's loaded beyond small per-slot summaries, budget cuts must be
detected and handled conservatively, and classification must stay
exactly as before."""

import socket
from contextlib import contextmanager
from datetime import timedelta

import pytest
from sqlalchemy import event

from app.core.enums import AssetCriticality, AssetType, DiscoveryResultOutcome, DiscoveryRunStatus
from app.services import attack_path_service as engine
from app.services import exposure_evidence_service as exposure
from app.services.exposure_evidence_service import EvidenceType, Freshness
from tests.attack_path_fixtures import (
    AS_OF,
    ago,
    http_result,
    make_asset,
    make_org,
    make_run,
    make_scan,
    observed_dns,
    port_result,
)
from tests.conftest import test_engine


@pytest.fixture
def org(db):
    return make_org(db, "Bounds Org")


@contextmanager
def _loaded():
    """Counts the rows the database returns (and statements run) while
    the block executes."""
    counts = {"rows": 0, "queries": 0}

    def after(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            counts["queries"] += 1
            counts["rows"] += max(cursor.rowcount, 0)

    event.listen(test_engine, "after_cursor_execute", after)
    try:
        yield counts
    finally:
        event.remove(test_engine, "after_cursor_execute", after)


def _assess(db, org_row, asset):
    return exposure.assess_asset_exposure(db, org_row.id, asset.id, as_of=AS_OF)


def _only(result, evidence_type):
    items = [e for e in result.evidence if e.evidence_type is evidence_type]
    assert len(items) == 1, items
    return items[0]


def _scan_port(db, user, ip, port, state, *, at):
    return port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=at), port, state)


# --- History length and density ------------------------------------------------------------


def test_long_stale_history_is_summarized_not_loaded(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "long-history.example.com")
    for days in range(200, 10, -1):  # 190 daily confirmations, the last one 11 days ago
        http_result(db, org_row, user, asset, "https", at=ago(days=days), outcome=DiscoveryResultOutcome.unchanged)
    db.flush()

    with _loaded() as counts:
        evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.freshness is Freshness.stale and not evidence.qualifies
    assert evidence.last_confirmed_at == ago(days=11) and evidence.first_confirmed_at == ago(days=200)
    assert counts["rows"] <= 6  # asset + latest + earliest; never the 190-row history
    assert "counted within the freshness window only" in " ".join(evidence.limitations)


def test_dense_recent_confirmations_load_one_row_per_slot(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "dense-ok.example.com")
    for minutes in range(1, 301):  # 300 confirmations in the last five hours
        http_result(db, org_row, user, asset, "https", at=AS_OF - timedelta(minutes=minutes))
    db.flush()

    with _loaded() as counts:
        evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.qualifies and evidence.last_confirmed_at == AS_OF - timedelta(minutes=1)
    assert evidence.first_confirmed_at == AS_OF - timedelta(minutes=300)
    assert counts["rows"] <= 6


def test_dense_recent_failures_are_capped_and_never_decide_qualification(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "dense-flaky.example.com")
    confirmed = http_result(db, org_row, user, asset, "https", at=ago(days=3))
    for minutes in range(1, 121):  # 120 inconclusive failures since
        http_result(db, org_row, user, asset, "https", at=ago(days=2) + timedelta(minutes=minutes),
                    outcome=DiscoveryResultOutcome.failed)
    db.flush()

    with _loaded() as counts:
        evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.qualifies and evidence.freshness is Freshness.current and evidence.result_id == confirmed.id
    assert evidence.inconclusive_attempts == exposure.INCONCLUSIVE_PER_ASSET
    assert evidence.latest_inconclusive_at == ago(days=2) + timedelta(minutes=120)
    assert "lower bound" in " ".join(evidence.limitations)
    assert counts["rows"] <= exposure.INCONCLUSIVE_PER_ASSET + 6


def test_failures_outside_the_window_are_never_loaded(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "old-failures.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=40))
    for days in range(39, 9, -1):  # 30 failures, all before the window
        http_result(db, org_row, user, asset, "https", at=ago(days=days), outcome=DiscoveryResultOutcome.failed)
    db.flush()

    with _loaded() as counts:
        evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.freshness is Freshness.stale and evidence.inconclusive_attempts == 0
    assert counts["rows"] <= 6


# --- Negatives and inconclusive attempts stay distinct ---------------------------------------


def test_negative_buried_under_dense_inconclusive_results_still_supersedes(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.90", AssetType.ip_address, authorization_confirmed=True)
    _scan_port(db, user, ip, 443, "open", at=ago(days=5))
    closed = _scan_port(db, user, ip, 443, "closed", at=ago(days=4))
    for hours in range(1, 61):  # 60 later filtered results bury the closed one
        _scan_port(db, user, ip, 443, "filtered", at=ago(days=3) + timedelta(hours=hours))
    db.flush()

    evidence = _only(_assess(db, org_row, ip), EvidenceType.open_port)

    assert evidence.freshness is Freshness.superseded and not evidence.qualifies
    assert evidence.contradicted_at == ago(days=4)
    assert closed.id is not None


def test_confirmation_after_negatives_is_current(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.91", AssetType.ip_address, authorization_confirmed=True)
    for days in (9, 6, 4):
        _scan_port(db, user, ip, 443, "closed", at=ago(days=days))
    _scan_port(db, user, ip, 443, "open", at=ago(days=1))

    evidence = _only(_assess(db, org_row, ip), EvidenceType.open_port)

    assert evidence.qualifies and evidence.contradicted_at is None


def test_confirmation_followed_by_inconclusive_attempts(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "then-flaky.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=6))
    http_result(db, org_row, user, asset, "https", at=ago(days=5), outcome=DiscoveryResultOutcome.failed)  # before the latest confirmation
    http_result(db, org_row, user, asset, "https", at=ago(days=4))
    for days in (3, 2):
        http_result(db, org_row, user, asset, "https", at=ago(days=days), outcome=DiscoveryResultOutcome.failed)
    make_run(db, org_row, user, asset, "http", at=ago(days=1), status=DiscoveryRunStatus.failed)

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.qualifies and evidence.last_confirmed_at == ago(days=4)
    assert evidence.inconclusive_attempts == 3 and evidence.latest_inconclusive_at == ago(days=1)


def test_equal_timestamps_resolve_the_same_way_under_density(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.92", AssetType.ip_address, authorization_confirmed=True)
    same = ago(days=1)
    for _ in range(3):
        _scan_port(db, user, ip, 443, "open", at=same)
    _scan_port(db, user, ip, 443, "closed", at=same)
    for _ in range(3):
        _scan_port(db, user, ip, 443, "open", at=same)

    first = _assess(db, org_row, ip)
    second = _assess(db, org_row, ip)

    evidence = _only(first, EvidenceType.open_port)
    assert evidence.freshness is Freshness.superseded and evidence.contradicted_at == same  # a tie goes against it
    assert first == second


# --- Budget limits and conservative handling ---------------------------------------------------


def test_budget_cut_on_latest_confirmations_is_flagged(db, org, monkeypatch):
    org_row, user = org
    assets = [make_asset(db, org_row, f"cut-{index}.example.com") for index in range(3)]
    for asset in assets:
        http_result(db, org_row, user, asset, "https", at=ago(days=1))
    monkeypatch.setattr(exposure, "EVIDENCE_ROW_BUDGET", 1)

    assessed = exposure.assess_exposure(db, org_row.id, as_of=AS_OF)

    ordered = sorted(assets, key=lambda asset: asset.id)  # UUID order, as the database sorts
    assert assessed[ordered[0].id].is_observed_entry_point and not assessed[ordered[0].id].evidence_truncated
    for asset in ordered[1:]:
        result = assessed[asset.id]
        assert result.evidence_truncated and not result.is_observed_entry_point  # missing, never invented
        assert "evidence budget" in " ".join(result.limitations)


def test_budget_cut_before_negatives_never_leaves_a_port_current(db, org, monkeypatch):
    org_row, user = org
    first = make_asset(db, org_row, "203.0.113.93", AssetType.ip_address, authorization_confirmed=True)
    second = make_asset(db, org_row, "203.0.113.94", AssetType.ip_address, authorization_confirmed=True)
    for ip in (first, second):
        _scan_port(db, user, ip, 443, "open", at=ago(days=2))
    _scan_port(db, user, second, 443, "closed", at=ago(days=1))  # second is really superseded
    # Exactly enough for the two latest confirmations: the negatives query
    # then runs with nothing left and is cut.
    monkeypatch.setattr(exposure, "EVIDENCE_ROW_BUDGET", 2)

    assessed = exposure.assess_exposure(db, org_row.id, as_of=AS_OF)

    port = _only(assessed[second.id], EvidenceType.open_port)
    assert not port.qualifies and port.freshness is Freshness.unknown
    assert "later results were checked" in port.limitations[0]
    assert assessed[second.id].evidence_truncated and not assessed[second.id].is_observed_entry_point
    for asset in (first, second):  # whichever side of the cut, nothing unverified counts as current
        item = _only(assessed[asset.id], EvidenceType.open_port)
        assert item.qualifies == (not assessed[asset.id].evidence_truncated)


def test_budget_cut_on_informational_queries_keeps_qualification(db, org, monkeypatch):
    org_row, user = org
    asset = make_asset(db, org_row, "informational-cut.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=2))
    http_result(db, org_row, user, asset, "https", at=ago(days=1), outcome=DiscoveryResultOutcome.failed)
    monkeypatch.setattr(exposure, "EVIDENCE_ROW_BUDGET", 1)  # the latest confirmation only

    result = _assess(db, org_row, asset)

    evidence = _only(result, EvidenceType.http_response)
    assert evidence.qualifies and not result.evidence_truncated
    assert evidence.first_confirmed_at is None
    joined = " ".join(evidence.limitations)
    assert "earliest confirmation wasn't determined" in joined and "weren't examined" in joined


def test_engine_reports_the_evidence_budget_as_a_truncation(db, org, monkeypatch):
    org_row, user = org
    database = make_asset(db, org_row, "198.51.100.95", AssetType.ip_address, criticality=AssetCriticality.critical)
    for index in range(3):
        site = make_asset(db, org_row, f"budget-{index}.example.com")
        http_result(db, org_row, user, site, "https", at=ago(days=1))
        observed_dns(db, org_row, user, site, database)
    monkeypatch.setattr(exposure, "EVIDENCE_ROW_BUDGET", 1)

    result = engine.find_exposure_paths(db, org_row.id, as_of=AS_OF)

    assert result.truncated and "evidence_budget" in [t.limit for t in result.truncations]
    assert len(result.paths) <= 1  # paths only through evidence that was fully examined


# --- Determinism, isolation, bounded retrieval, no network -------------------------------------


def test_bounded_results_are_deterministic(db, org, monkeypatch):
    org_row, user = org
    for index in range(4):
        asset = make_asset(db, org_row, f"det-bound-{index}.example.com")
        for hours in (30, 20, 10):
            http_result(db, org_row, user, asset, "https", at=ago(hours=hours))
            http_result(db, org_row, user, asset, "http", at=ago(hours=hours), outcome=DiscoveryResultOutcome.failed)
    monkeypatch.setattr(exposure, "EVIDENCE_ROW_BUDGET", 7)

    runs = [exposure.assess_exposure(db, org_row.id, as_of=AS_OF) for _ in range(3)]

    assert runs[0] == runs[1] == runs[2]


def test_another_organizations_history_is_never_loaded(db, org):
    org_row, user = org
    other_org, other_user = make_org(db, "Noisy Neighbour Org")
    theirs = make_asset(db, other_org, "noisy.example.com")
    for minutes in range(1, 151):
        http_result(db, other_org, other_user, theirs, "https", at=AS_OF - timedelta(minutes=minutes),
                    outcome=DiscoveryResultOutcome.failed)
    mine = make_asset(db, org_row, "quiet.example.com")
    http_result(db, org_row, user, mine, "https", at=ago(days=1))
    # A run recorded under the other organization that points at this
    # organization's asset never counts either.
    http_result(db, other_org, other_user, mine, "http", at=ago(hours=1))
    db.flush()

    with _loaded() as counts:
        assessed = exposure.assess_exposure(db, org_row.id, as_of=AS_OF)

    assert set(assessed) == {mine.id}
    assert [e.subject for e in assessed[mine.id].evidence] == ["https"]
    assert counts["rows"] <= 6


def test_rows_loaded_do_not_grow_with_history(db, org):
    org_row, user = org

    def rows_for(prefix: str, history: int) -> int:
        ip = make_asset(db, org_row, f"198.51.{100 + history}.96", AssetType.ip_address, authorization_confirmed=True)
        site = make_asset(db, org_row, f"{prefix}.example.com")
        for days in range(history, 0, -1):
            http_result(db, org_row, user, site, "https", at=ago(days=days))
            _scan_port(db, user, ip, 443, "open" if days % 2 else "filtered", at=ago(days=days))
        db.flush()
        with _loaded() as counts:
            exposure.assess_exposure(db, org_row.id, [site.id, ip.id], as_of=AS_OF)
        return counts["rows"]

    # Same last seven days (inconclusive attempts inside the window are
    # loaded, capped per asset); only the history before the window differs.
    assert rows_for("short", 8) == rows_for("long", 60)


def test_bounded_assessment_is_offline(db, org, monkeypatch):
    org_row, user = org
    asset = make_asset(db, org_row, "offline-bounds.example.com")
    for hours in range(1, 40):
        http_result(db, org_row, user, asset, "https", at=ago(hours=hours),
                    outcome=DiscoveryResultOutcome.failed if hours % 3 else DiscoveryResultOutcome.unchanged)
    monkeypatch.setattr(exposure, "EVIDENCE_ROW_BUDGET", 5)

    def refuse(*args, **kwargs):
        raise AssertionError("bounded evidence retrieval attempted network access")

    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)

    assert _assess(db, org_row, asset).is_observed_entry_point is True
