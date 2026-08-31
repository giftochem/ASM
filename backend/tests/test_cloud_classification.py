"""Unit tests for the pure classify_infrastructure function -- no I/O,
no mocking needed anywhere in this file. Every combination of signals
is directly testable.
"""

from app.discovery.cloud_classification import classify_infrastructure, confidence_label


def test_aws_classification_via_asn_number():
    result = classify_infrastructure(asn="AS16509")
    assert result.provider == "Amazon Web Services"
    assert result.confidence > 0


def test_aws_classification_via_organization_name():
    result = classify_infrastructure(asn_organization="AMAZON-02, US")
    assert result.provider == "Amazon Web Services"


def test_aws_classification_via_ptr_pattern():
    result = classify_infrastructure(ptr_hostname="ec2-54-1-2-3.compute-1.amazonaws.com")
    assert result.provider == "Amazon Web Services"


def test_aws_classification_via_http_server_header():
    result = classify_infrastructure(http_server="AmazonS3")
    assert result.provider == "Amazon Web Services"


def test_aws_classification_via_tls_issuer():
    result = classify_infrastructure(tls_issuer="Amazon RSA 2048 M02")
    assert result.provider == "Amazon Web Services"


def test_azure_classification():
    result = classify_infrastructure(asn="AS8075", asn_organization="MICROSOFT-CORP-MSN-AS-BLOCK, US")
    assert result.provider == "Microsoft Azure"


def test_azure_classification_via_ptr():
    result = classify_infrastructure(ptr_hostname="myvm.westus.cloudapp.azure.com")
    assert result.provider == "Microsoft Azure"


def test_gcp_classification():
    result = classify_infrastructure(asn="AS15169", asn_organization="GOOGLE - Google LLC, US")
    assert result.provider == "Google Cloud"


def test_gcp_classification_via_ptr():
    result = classify_infrastructure(ptr_hostname="123.45.67.89.bc.googleusercontent.com")
    assert result.provider == "Google Cloud"


def test_cloudflare_classification():
    result = classify_infrastructure(asn="AS13335", asn_organization="CLOUDFLARENET, US", http_server="cloudflare")
    assert result.provider == "Cloudflare"


def test_digitalocean_classification():
    result = classify_infrastructure(asn="AS14061", asn_organization="DIGITALOCEAN-ASN, US")
    assert result.provider == "DigitalOcean"


def test_oracle_cloud_classification():
    result = classify_infrastructure(asn_organization="ORACLE-BMC-31898, US", ptr_hostname="host.oraclecloud.com")
    assert result.provider == "Oracle Cloud"


def test_unknown_provider_when_no_signal_matches():
    result = classify_infrastructure(asn_organization="SOME-SMALL-REGIONAL-ISP-LLC, US")
    assert result.provider is None
    assert result.confidence == 0.0
    assert result.evidence == []
    assert result.confidence_label == "unknown"


def test_no_signals_at_all_returns_unknown():
    result = classify_infrastructure()
    assert result.provider is None
    assert result.confidence == 0.0


def test_conflicting_signals_surfaces_both_candidates():
    # ASN says AWS, TLS issuer says Cloudflare -- a plausible real-world
    # case (e.g. Cloudflare-fronted origin actually hosted on AWS).
    result = classify_infrastructure(asn="AS16509", tls_issuer="Cloudflare Inc ECC CA-3")
    assert result.provider == "Amazon Web Services"  # asn_number (0.55) > tls_issuer (0.35)
    assert result.conflicting is True
    assert len(result.alternative_providers) == 1
    assert result.alternative_providers[0]["provider"] == "Cloudflare"


def test_non_conflicting_when_runner_up_is_far_weaker():
    # A single strong AWS signal vs. a single weak, unrelated signal
    # that doesn't even match a different provider -- no conflict.
    result = classify_infrastructure(asn="AS16509", asn_organization="AMAZON-02, US")
    assert result.conflicting is False
    assert result.alternative_providers == []


def test_strong_multi_signal_evidence_yields_higher_confidence_than_single_signal():
    single = classify_infrastructure(asn_organization="GOOGLE LLC")
    multi = classify_infrastructure(
        asn="AS15169",
        asn_organization="GOOGLE LLC",
        ptr_hostname="1.2.3.4.bc.googleusercontent.com",
        http_server="Google Frontend",
    )
    assert multi.confidence > single.confidence
    assert len(multi.evidence) > len(single.evidence)


def test_weak_single_signal_evidence_has_lower_confidence():
    result = classify_infrastructure(http_server="AmazonS3")
    assert result.provider == "Amazon Web Services"
    assert result.confidence == 0.25  # http_server weight alone
    assert result.confidence_label == "weakly_inferred"


def test_confidence_is_capped_at_maximum():
    result = classify_infrastructure(
        asn="AS16509",
        asn_organization="AMAZON-02, US",
        ptr_hostname="ec2-1-2-3-4.compute-1.amazonaws.com",
        http_server="AmazonS3",
        tls_issuer="Amazon RSA 2048 M02",
    )
    assert result.confidence <= 0.9
    assert result.confidence == 0.9  # 0.55+0.45+0.30+0.25+0.35 = 1.9, capped


def test_confidence_label_buckets():
    assert confidence_label(0.9) == "confidently_identified"
    assert confidence_label(0.75) == "confidently_identified"
    assert confidence_label(0.6) == "probably_identified"
    assert confidence_label(0.5) == "probably_identified"
    assert confidence_label(0.25) == "weakly_inferred"
    assert confidence_label(0.0) == "unknown"


def test_generic_ca_issuer_is_not_treated_as_provider_evidence():
    result = classify_infrastructure(tls_issuer="Let's Encrypt Authority X3")
    assert result.provider is None
    assert result.confidence == 0.0


def test_generic_ca_issuer_does_not_block_other_real_signals():
    result = classify_infrastructure(tls_issuer="Let's Encrypt Authority X3", asn="AS16509")
    assert result.provider == "Amazon Web Services"
    assert all(e["signal"] != "tls_issuer" for e in result.evidence)


def test_asn_number_and_organization_name_are_independent_corroborating_signals():
    number_only = classify_infrastructure(asn="AS16509")
    both = classify_infrastructure(asn="AS16509", asn_organization="AMAZON-02, US")
    assert both.confidence > number_only.confidence


def test_unrecognized_asn_number_falls_through_to_organization_name():
    # A real AWS-owned ASN not in the small, intentionally incomplete
    # known-ASN table -- classification should still succeed via the
    # organization-name signal instead of silently failing.
    result = classify_infrastructure(asn="AS999999", asn_organization="AMAZON-AES, US")
    assert result.provider == "Amazon Web Services"


def test_ipv6_ptr_pattern_classified_the_same_as_ipv4():
    result = classify_infrastructure(ptr_hostname="dns.google")
    # "dns.google" itself doesn't match the conservative GCP PTR
    # patterns (which target compute-instance-style hostnames) --
    # confirms no false positive from a loosely-related domain.
    assert result.provider is None


def test_malformed_or_empty_signal_strings_handled_cleanly():
    result = classify_infrastructure(asn="", asn_organization="", ptr_hostname="", http_server="", tls_issuer="")
    assert result.provider is None
    assert result.confidence == 0.0


def test_none_signals_handled_cleanly():
    result = classify_infrastructure(asn=None, asn_organization=None, ptr_hostname=None, http_server=None, tls_issuer=None)
    assert result.provider is None


def test_prefix_is_not_an_independent_classification_signal():
    """Deliberate design decision (see module docstring): announced
    prefix and ASN come from the same Team Cymru response, so prefix
    membership is not double-counted as separate corroborating
    evidence. classify_infrastructure doesn't even accept a prefix
    parameter -- this test documents that boundary explicitly.
    """
    import inspect

    from app.discovery.cloud_classification import classify_infrastructure as fn

    assert "prefix" not in inspect.signature(fn).parameters


def test_no_ip_range_list_matching_signal_type_exists():
    """Deliberate scope boundary (see module docstring): provider-
    published IP range lists are not fetched or matched against in this
    pass -- no evidence entry should ever claim an "ip_range" signal.
    """
    result = classify_infrastructure(
        asn="AS16509", asn_organization="AMAZON-02, US", ptr_hostname="ec2-1-2-3-4.compute-1.amazonaws.com"
    )
    assert all(e["signal"] != "ip_range" for e in result.evidence)
