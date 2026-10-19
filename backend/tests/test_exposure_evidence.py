"""Stage A.2: observed external-exposure evidence
(app.services.exposure_evidence_service). Synthetic rows only, written
with explicit timestamps and assessed at a fixed AS_OF."""

import socket
from datetime import timedelta

import pytest

from app.core.enums import AssetType, ChangeType, DiscoveryResultOutcome, DiscoveryRunStatus, LifecycleStatus, ScanStatus
from app.discovery import registry
from app.models.discovery_result import DiscoveryResult
from app.services import exposure_evidence_service as exposure
from app.services.exposure_evidence_service import EvidenceType, Freshness
from tests.attack_path_fixtures import (
    AS_OF,
    ago,
    certificate_row,
    http_result,
    make_asset,
    make_org,
    make_run,
    make_scan,
    observation,
    port_result,
    ssl_result,
    tls_result,
)

DNS_FAILURE = (
    "blocked target 'https://flaky.example.com/': DNS resolution failed for 'flaky.example.com': "
    "[Errno -3] Temporary failure in name resolution"
)


@pytest.fixture
def org(db):
    return make_org(db, "Exposure Org")


def _assess(db, org_row, asset, **kwargs):
    return exposure.assess_asset_exposure(db, org_row.id, asset.id, as_of=AS_OF, **kwargs)


def _only(result, evidence_type):
    items = [e for e in result.evidence if e.evidence_type is evidence_type]
    assert len(items) == 1, items
    return items[0]


def _http_failure(db, org_row, user, asset, scheme, *, at, reason):
    result = http_result(db, org_row, user, asset, scheme, at=at, outcome=DiscoveryResultOutcome.failed)
    result.evidence = {**result.evidence, "failure_reason": reason}
    db.flush()
    return result


# --- 1. HTTP -------------------------------------------------------------------------


def test_http_response_establishes_observed_exposure(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "app.example.com")
    first = http_result(db, org_row, user, asset, "https", at=ago(days=5))
    latest = http_result(db, org_row, user, asset, "https", at=ago(days=1), outcome=DiscoveryResultOutcome.unchanged)
    obs = observation(db, asset, ChangeType.http_observed, at=ago(days=5), field_name="http:https", current_value="{}")

    result = _assess(db, org_row, asset)

    assert result.is_observed_entry_point is True
    evidence = _only(result, EvidenceType.http_response)
    assert evidence.qualifies and evidence.freshness is Freshness.current
    assert evidence.source == "discovery:http" and evidence.subject == "https"
    assert evidence.first_confirmed_at == first.created_at and evidence.last_confirmed_at == latest.created_at
    assert evidence.result_id == latest.id and evidence.discovery_run_id == latest.discovery_run_id
    assert evidence.observation_id == obs.id
    assert evidence.inconclusive_attempts == 0 and evidence.contradicted_at is None and evidence.limitations == ()


@pytest.mark.parametrize("status_code", [403, 404, 500])
def test_error_status_codes_mean_the_endpoint_responded(db, org, status_code):
    org_row, user = org
    asset = make_asset(db, org_row, f"status-{status_code}.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=3), status_code=200)
    later = http_result(db, org_row, user, asset, "https", at=ago(days=1), status_code=status_code,
                        outcome=DiscoveryResultOutcome.refreshed)

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    # A later error status re-confirms the service; it never counts against it.
    assert evidence.qualifies and evidence.freshness is Freshness.current
    assert evidence.last_confirmed_at == later.created_at and evidence.result_id == later.id


def test_failed_and_rejected_http_attempts_alone_establish_nothing(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "down.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=1), outcome=DiscoveryResultOutcome.failed)
    http_result(db, org_row, user, asset, "http", at=ago(days=1), outcome=DiscoveryResultOutcome.rejected)

    result = _assess(db, org_row, asset)

    assert result.is_observed_entry_point is False
    assert not [e for e in result.evidence if e.evidence_type is EvidenceType.http_response]


def test_http_observation_without_an_attributable_result_never_qualifies(db, org):
    org_row, _ = org
    asset = make_asset(db, org_row, "orphan.example.com")
    observation(db, asset, ChangeType.http_observed, at=ago(hours=1), field_name="http:https", current_value='{"status_code": 200}')

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.qualifies is False and evidence.source == "observation"
    assert "no attributable provider result" in " ".join(evidence.limitations)


# --- Correction 1: inconclusive failures ---------------------------------------------


def test_temporary_dns_failure_after_http_evidence_is_inconclusive(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "flaky.example.com")
    confirmed = http_result(db, org_row, user, asset, "https", at=ago(days=3))
    _http_failure(db, org_row, user, asset, "https", at=ago(days=1), reason=DNS_FAILURE)

    result = _assess(db, org_row, asset)

    evidence = _only(result, EvidenceType.http_response)
    assert result.is_observed_entry_point and evidence.qualifies and evidence.freshness is Freshness.current
    assert evidence.last_confirmed_at == confirmed.created_at and evidence.result_id == confirmed.id
    assert evidence.inconclusive_attempts == 1 and evidence.latest_inconclusive_at == ago(days=1)
    assert evidence.latest_attempt_at == ago(days=1) and evidence.contradicted_at is None
    assert "inconclusive" in evidence.limitations[0] and "free text" in evidence.limitations[0]


def test_timeout_after_http_evidence_is_inconclusive(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "slow.example.com")
    http_result(db, org_row, user, asset, "http", at=ago(days=2))
    _http_failure(db, org_row, user, asset, "http", at=ago(hours=6), reason="timed out")

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.qualifies and evidence.freshness is Freshness.current and evidence.inconclusive_attempts == 1


def test_failure_text_is_never_parsed_into_a_negative(db, org):
    """Even wording that sounds definitive stays inconclusive: the provider
    stores failures only as free text, and this module doesn't guess."""
    org_row, user = org
    asset = make_asset(db, org_row, "refused.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=2))
    _http_failure(db, org_row, user, asset, "https", at=ago(days=1), reason="[Errno 111] Connection refused")

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.freshness is Freshness.current and evidence.contradicted_at is None


def test_out_of_scope_redirect_is_inconclusive(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "redirects.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=2))
    http_result(db, org_row, user, asset, "https", at=ago(days=1), outcome=DiscoveryResultOutcome.rejected)

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.qualifies and evidence.inconclusive_attempts == 1
    assert "outside the authorized scope" in " ".join(evidence.limitations)


def test_failed_http_run_is_inconclusive(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "run-failed.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=2))
    make_run(db, org_row, user, asset, "http", at=ago(days=1), status=DiscoveryRunStatus.failed)

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.qualifies and evidence.inconclusive_attempts == 1


def test_evidence_becomes_stale_after_seven_days_despite_inconclusive_failures(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "fading.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=8))
    _http_failure(db, org_row, user, asset, "https", at=ago(days=5), reason=DNS_FAILURE)
    _http_failure(db, org_row, user, asset, "https", at=ago(days=1), reason="timed out")

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    # Inconclusive attempts neither refresh nor contradict it: it ages out.
    assert evidence.freshness is Freshness.stale and evidence.qualifies is False
    assert evidence.last_confirmed_at == ago(days=8) and evidence.inconclusive_attempts == 2
    assert evidence.limitations[0].startswith("last confirmed")


def test_freshness_window_boundary_is_seven_days(db, org):
    org_row, user = org
    inside = make_asset(db, org_row, "inside.example.com")
    outside = make_asset(db, org_row, "outside.example.com")
    http_result(db, org_row, user, inside, "https", at=AS_OF - timedelta(days=7))
    http_result(db, org_row, user, outside, "https", at=AS_OF - timedelta(days=7, seconds=1))

    assert exposure.FRESHNESS_WINDOW == timedelta(days=7)
    assert _assess(db, org_row, inside).is_observed_entry_point is True
    assert _assess(db, org_row, outside).is_observed_entry_point is False


# --- 2. TLS --------------------------------------------------------------------------


def test_tls_handshake_establishes_observed_tls_exposure(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "tls.example.com")
    certificate_row(db, asset, at=ago(days=2))
    handshake = tls_result(db, org_row, user, asset, at=ago(days=2))

    result = _assess(db, org_row, asset)

    evidence = _only(result, EvidenceType.tls_handshake)
    assert result.is_observed_entry_point and evidence.qualifies
    assert evidence.subject == "tls.example.com:443" and evidence.result_id == handshake.id
    assert not [e for e in result.evidence if e.evidence_type is EvidenceType.certificate_record]


def test_certificate_record_alone_is_not_exposure(db, org):
    org_row, _ = org
    asset = make_asset(db, org_row, "certonly.example.com")
    certificate_row(db, asset, at=ago(hours=1))

    result = _assess(db, org_row, asset)

    evidence = _only(result, EvidenceType.certificate_record)
    assert result.is_observed_entry_point is False
    assert evidence.qualifies is False and evidence.freshness is Freshness.unknown
    assert evidence.last_confirmed_at is None  # no timestamp is borrowed from the inventory row
    assert "certificate record alone" in " ".join(evidence.limitations)


def test_tls_evidence_survives_an_inconclusive_failed_handshake_run(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "tls-flaky.example.com")
    handshake = tls_result(db, org_row, user, asset, at=ago(days=3))
    make_run(db, org_row, user, asset, "certificate", at=ago(days=1), status=DiscoveryRunStatus.failed)

    evidence = _only(_assess(db, org_row, asset), EvidenceType.tls_handshake)

    assert evidence.qualifies and evidence.freshness is Freshness.current and evidence.result_id == handshake.id
    assert evidence.inconclusive_attempts == 1 and evidence.latest_inconclusive_at == ago(days=1)
    assert "certificate discovery run failed" in " ".join(evidence.limitations)


def test_ssl_scan_handshake_establishes_tls_exposure(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "scanned-tls.example.com", authorization_confirmed=True)
    scan = make_scan(db, user, asset, ["ssl"], completed_at=ago(days=1))
    row = ssl_result(db, scan, asset)

    evidence = _only(_assess(db, org_row, asset), EvidenceType.tls_handshake)

    assert evidence.qualifies and evidence.source == "scan:ssl"
    assert evidence.scan_id == scan.id and evidence.result_id == row.id


def test_ssl_scan_that_stored_nothing_later_is_inconclusive(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "ssl-flaky.example.com", authorization_confirmed=True)
    ssl_result(db, make_scan(db, user, asset, ["ssl"], completed_at=ago(days=3)), asset)
    make_scan(db, user, asset, ["ssl"], completed_at=ago(days=1))  # module couldn't complete

    evidence = _only(_assess(db, org_row, asset), EvidenceType.tls_handshake)

    assert evidence.qualifies and evidence.inconclusive_attempts == 1


# --- 3. Open ports ------------------------------------------------------------------


def test_open_port_from_completed_scan_establishes_exposure(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.10", AssetType.ip_address, authorization_confirmed=True)
    scan = make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1))
    port_result(db, scan, 22, "closed")
    row = port_result(db, scan, 443, "open")

    result = _assess(db, org_row, ip)

    evidence = _only(result, EvidenceType.open_port)  # closed ports produce no evidence
    assert result.is_observed_entry_point and evidence.subject == "443/tcp"
    assert evidence.scan_id == scan.id and evidence.result_id == row.id
    assert evidence.last_confirmed_at == scan.completed_at


def test_definitive_closed_port_supersedes_earlier_open(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.11", AssetType.ip_address, authorization_confirmed=True)
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=3)), 443, "open")
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1)), 443, "closed")

    evidence = _only(_assess(db, org_row, ip), EvidenceType.open_port)

    assert evidence.freshness is Freshness.superseded and evidence.qualifies is False
    assert evidence.contradicted_at == ago(days=1) and "connection was refused" in evidence.limitations[0]


def test_reopened_port_after_closed_is_current_again(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.15", AssetType.ip_address, authorization_confirmed=True)
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=3)), 443, "closed")
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1)), 443, "open")

    evidence = _only(_assess(db, org_row, ip), EvidenceType.open_port)

    assert evidence.qualifies and evidence.contradicted_at is None


def test_filtered_port_after_open_is_inconclusive(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.16", AssetType.ip_address, authorization_confirmed=True)
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=3)), 443, "open")
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1)), 443, "filtered")

    evidence = _only(_assess(db, org_row, ip), EvidenceType.open_port)

    assert evidence.qualifies and evidence.freshness is Freshness.current
    assert evidence.inconclusive_attempts == 1 and "filtered" in evidence.limitations[0]


def test_port_scan_that_stored_nothing_later_is_inconclusive(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.12", AssetType.ip_address, authorization_confirmed=True)
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=3)), 443, "open")
    make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1))  # blocked target / DNS failure

    evidence = _only(_assess(db, org_row, ip), EvidenceType.open_port)

    assert evidence.qualifies and evidence.inconclusive_attempts == 1


@pytest.mark.parametrize("status", [ScanStatus.failed, ScanStatus.cancelled, ScanStatus.running, ScanStatus.queued])
def test_open_port_from_unfinished_or_failed_scan_does_not_count(db, org, status):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.13", AssetType.ip_address, authorization_confirmed=True)
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1), status=status), 443, "open")

    assert _assess(db, org_row, ip).is_observed_entry_point is False


# --- Same-time events and deterministic ordering --------------------------------------


@pytest.mark.parametrize("insert_order", [("open", "closed"), ("closed", "open")])
def test_same_time_closed_and_open_resolve_against_the_confirmation(db, org, insert_order):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.17", AssetType.ip_address, authorization_confirmed=True)
    for state in insert_order:
        port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1)), 443, state)

    evidence = _only(_assess(db, org_row, ip), EvidenceType.open_port)

    # Simultaneous contradictory observations can't be ordered: the
    # negative wins the tie, whichever row was written first.
    assert evidence.freshness is Freshness.superseded and evidence.contradicted_at == ago(days=1)


def test_same_time_inconclusive_attempt_does_not_invalidate(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "same-time.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=1))
    _http_failure(db, org_row, user, asset, "https", at=ago(days=1), reason="timed out")

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.qualifies and evidence.inconclusive_attempts == 1


def test_same_time_confirmations_pick_the_anchor_deterministically(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "twins.example.com")
    one = http_result(db, org_row, user, asset, "https", at=ago(days=1))
    two = http_result(db, org_row, user, asset, "https", at=ago(days=1), outcome=DiscoveryResultOutcome.unchanged)

    picks = {_only(_assess(db, org_row, asset), EvidenceType.http_response).result_id for _ in range(5)}

    assert picks == {max((one.id, two.id), key=str)}


def test_results_are_deterministic(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "stable.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=1))
    http_result(db, org_row, user, asset, "http", at=ago(days=2))
    _http_failure(db, org_row, user, asset, "http", at=ago(days=1), reason="timed out")
    tls_result(db, org_row, user, asset, at=ago(days=1))
    observation(db, asset, ChangeType.dns_records_observed, at=ago(days=1), field_name="dns_metadata")
    make_asset(db, org_row, "other-stable.example.com")

    first = exposure.assess_exposure(db, org_row.id, as_of=AS_OF)
    second = exposure.assess_exposure(db, org_row.id, as_of=AS_OF)

    assert first == second and list(first) == list(second)
    assert [e.evidence_type for e in first[asset.id].evidence] == [
        EvidenceType.http_response, EvidenceType.http_response, EvidenceType.tls_handshake, EvidenceType.dns_records,
    ]


# --- 4/5. DNS-only and asset-type-only -----------------------------------------------


def test_dns_records_alone_are_not_exposure(db, org):
    org_row, _ = org
    asset = make_asset(db, org_row, "dnsonly.example.com")
    observation(db, asset, ChangeType.dns_records_observed, at=ago(hours=2), field_name="dns_metadata", current_value="{}")
    observation(db, asset, ChangeType.certificate_transparency_observed, at=ago(hours=2), field_name="discovery_metadata")

    result = _assess(db, org_row, asset)

    assert result.is_observed_entry_point is False
    assert _only(result, EvidenceType.dns_records).qualifies is False
    assert _only(result, EvidenceType.certificate_transparency).qualifies is False


@pytest.mark.parametrize(
    "asset_type,value",
    [(AssetType.domain, "bare.example.com"), (AssetType.ip_address, "198.51.100.7"), (AssetType.url, "https://bare.example.com/")],
)
def test_asset_type_alone_is_not_exposure(db, org, asset_type, value):
    org_row, _ = org
    asset = make_asset(db, org_row, value, asset_type)

    result = _assess(db, org_row, asset)

    assert result.is_observed_entry_point is False and result.evidence == ()
    assert f"asset type '{asset_type.value}' alone does not establish exposure" in result.limitations


# --- 6. Freshness --------------------------------------------------------------------


def test_old_evidence_is_stale_not_current(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "old.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=10))

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)

    assert evidence.freshness is Freshness.stale and evidence.qualifies is False
    assert evidence.last_confirmed_at == ago(days=10)


def test_missing_confirmation_time_is_unknown_not_current(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.14", AssetType.ip_address, authorization_confirmed=True)
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=None), 443, "open")

    evidence = _only(_assess(db, org_row, ip), EvidenceType.open_port)

    assert evidence.freshness is Freshness.unknown and evidence.qualifies is False
    assert evidence.last_confirmed_at is None and evidence.first_confirmed_at is None


def test_freshness_window_is_configurable(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "window.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=10))

    result = _assess(db, org_row, asset, freshness_window=timedelta(days=14))

    assert result.is_observed_entry_point is True


def test_evidence_after_as_of_is_ignored(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "future.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(days=1))

    earlier = exposure.assess_asset_exposure(db, org_row.id, asset.id, as_of=ago(days=2))

    assert earlier.is_observed_entry_point is False and earlier.evidence == ()


def test_disappeared_asset_evidence_does_not_qualify(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "vanished.example.com", status=LifecycleStatus.disappeared)
    http_result(db, org_row, user, asset, "https", at=ago(hours=1))

    result = _assess(db, org_row, asset)

    assert result.is_observed_entry_point is False
    assert _only(result, EvidenceType.http_response).qualifies is False


# --- 7. Fabricated / test-only provider results --------------------------------------


@pytest.mark.parametrize("provider", ["stub", "made_up_provider"])
@pytest.mark.parametrize(
    "outcome", [DiscoveryResultOutcome.observed, DiscoveryResultOutcome.created, DiscoveryResultOutcome.unchanged]
)
def test_test_only_or_unknown_provider_results_never_qualify(db, org, provider, outcome):
    org_row, user = org
    asset = make_asset(db, org_row, "stubbed.example.com")
    # Shaped exactly like real HTTP evidence, under every confirming outcome.
    http_result(db, org_row, user, asset, "https", at=ago(hours=1), provider=provider, outcome=outcome)

    result = _assess(db, org_row, asset)

    assert result.is_observed_entry_point is False and result.evidence == ()


@pytest.mark.parametrize("run_status", [DiscoveryRunStatus.running, DiscoveryRunStatus.queued, DiscoveryRunStatus.cancelled])
def test_results_from_unfinished_runs_never_qualify(db, org, run_status):
    org_row, user = org
    asset = make_asset(db, org_row, "unfinished.example.com")
    http_result(db, org_row, user, asset, "https", at=ago(hours=1), run_status=run_status)

    assert _assess(db, org_row, asset).is_observed_entry_point is False


def test_evidence_providers_are_real_registered_providers():
    for name in exposure.EVIDENCE_PROVIDERS:
        provider = registry.DISCOVERY_PROVIDER_REGISTRY.get(name)
        assert provider is not None and provider.test_only is False, name
    test_only = {name for name, provider in registry.DISCOVERY_PROVIDER_REGISTRY.items() if provider.test_only}
    assert test_only and not (test_only & exposure.EVIDENCE_PROVIDERS)


def test_failures_alone_never_fabricate_evidence(db, org):
    org_row, user = org
    host = make_asset(db, org_row, "never-up.example.com", authorization_confirmed=True)
    ip = make_asset(db, org_row, "203.0.113.18", AssetType.ip_address, authorization_confirmed=True)
    _http_failure(db, org_row, user, host, "https", at=ago(days=1), reason=DNS_FAILURE)
    http_result(db, org_row, user, host, "http", at=ago(days=1), outcome=DiscoveryResultOutcome.rejected)
    make_run(db, org_row, user, host, "certificate", at=ago(days=1), status=DiscoveryRunStatus.failed)
    make_scan(db, user, host, ["ssl"], completed_at=ago(days=1))
    scan = make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1))
    port_result(db, scan, 443, "filtered")
    port_result(db, scan, 80, "closed")

    assessed = exposure.assess_exposure(db, org_row.id, as_of=AS_OF)

    for asset in (host, ip):
        assert assessed[asset.id].is_observed_entry_point is False
        assert assessed[asset.id].evidence == ()
        assert "no HTTP response, TLS handshake or open port has been observed" in assessed[asset.id].limitations


def test_reported_timestamps_are_stored_values(db, org):
    org_row, user = org
    asset = make_asset(db, org_row, "timestamps.example.com")
    first = http_result(db, org_row, user, asset, "https", at=ago(days=4, hours=3))
    last = http_result(db, org_row, user, asset, "https", at=ago(days=2, minutes=7), outcome=DiscoveryResultOutcome.unchanged)
    failure = _http_failure(db, org_row, user, asset, "https", at=ago(days=1, seconds=11), reason="timed out")

    evidence = _only(_assess(db, org_row, asset), EvidenceType.http_response)
    stored = {row.created_at for row in db.query(DiscoveryResult).all()}

    assert evidence.first_confirmed_at == first.created_at and evidence.last_confirmed_at == last.created_at
    assert evidence.latest_attempt_at == failure.created_at == evidence.latest_inconclusive_at
    assert {evidence.first_confirmed_at, evidence.last_confirmed_at, evidence.latest_attempt_at} <= stored


# --- 8. Organization isolation -------------------------------------------------------


def test_another_organizations_assets_are_never_assessed(db, org):
    org_row, user = org
    other_org, other_user = make_org(db, "Other Org")
    theirs = make_asset(db, other_org, "theirs.example.com")
    http_result(db, other_org, other_user, theirs, "https", at=ago(hours=1))
    mine = make_asset(db, org_row, "mine.example.com")

    assert exposure.assess_asset_exposure(db, org_row.id, theirs.id, as_of=AS_OF) is None
    assert set(exposure.assess_exposure(db, org_row.id, as_of=AS_OF)) == {mine.id}
    assert set(exposure.assess_exposure(db, org_row.id, [theirs.id, mine.id], as_of=AS_OF)) == {mine.id}


def test_runs_recorded_under_another_organization_are_ignored(db, org):
    org_row, _ = org
    other_org, other_user = make_org(db, "Foreign Run Org")
    mine = make_asset(db, org_row, "target.example.com")
    # A run row claiming another organization, pointed at this org's asset.
    http_result(db, other_org, other_user, mine, "https", at=ago(hours=1))

    assert _assess(db, org_row, mine).is_observed_entry_point is False


def test_results_about_another_asset_are_ignored(db, org):
    org_row, user = org
    seed = make_asset(db, org_row, "seed.example.com")
    other = make_asset(db, org_row, "other.example.com")
    result = http_result(db, org_row, user, seed, "https", at=ago(hours=1))
    result.resulting_asset_id = other.id
    db.flush()

    assessed = exposure.assess_exposure(db, org_row.id, as_of=AS_OF)

    assert assessed[seed.id].is_observed_entry_point is False
    assert assessed[other.id].is_observed_entry_point is False


# --- 15. No network ------------------------------------------------------------------


def test_assessment_makes_no_network_calls(db, org, monkeypatch):
    org_row, user = org
    asset = make_asset(db, org_row, "offline.example.com", authorization_confirmed=True)
    http_result(db, org_row, user, asset, "https", at=ago(days=2))
    _http_failure(db, org_row, user, asset, "https", at=ago(days=1), reason=DNS_FAILURE)
    make_run(db, org_row, user, asset, "certificate", at=ago(days=1), status=DiscoveryRunStatus.failed)
    port_result(db, make_scan(db, user, asset, ["port_scanner"], completed_at=ago(days=1)), 443, "filtered")

    def refuse(*args, **kwargs):
        raise AssertionError("exposure assessment attempted network access")

    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)

    assert exposure.assess_exposure(db, org_row.id, as_of=AS_OF)[asset.id].is_observed_entry_point is True
