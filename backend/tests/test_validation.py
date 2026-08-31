import pytest

from app.core.enums import AssetType
from app.core.exceptions import InvalidTargetError
from app.core.validation import is_hostname_in_scope, normalize_asset_value, validate_ip_range, validate_url


def test_domain_is_lowercased():
    assert normalize_asset_value(AssetType.domain, "Example.COM", 20) == "example.com"


def test_domain_rejects_bad_label():
    with pytest.raises(InvalidTargetError):
        normalize_asset_value(AssetType.domain, "-bad-.example.com", 20)


def test_domain_rejects_single_label():
    with pytest.raises(InvalidTargetError):
        normalize_asset_value(AssetType.domain, "localhost", 20)


def test_domain_rejects_shell_metacharacters():
    with pytest.raises(InvalidTargetError):
        normalize_asset_value(AssetType.domain, "example.com; rm -rf /", 20)


def test_ip_address_rejects_loopback():
    with pytest.raises(InvalidTargetError):
        normalize_asset_value(AssetType.ip_address, "127.0.0.1", 20)


def test_ip_address_accepts_valid_public_ip():
    assert normalize_asset_value(AssetType.ip_address, "93.184.216.34", 20) == "93.184.216.34"


def test_ip_range_within_cap_is_accepted():
    # 203.0.113.0/24 (RFC 5737 TEST-NET-3) can't be used here: Python's
    # ipaddress module classifies documentation ranges as `is_private`,
    # which Phase 3a's validation now correctly rejects (see
    # test_ip_range_rejects_private_range below) — so this needs a
    # genuinely public range instead.
    assert validate_ip_range("8.8.8.0/24", max_ipv4_prefix_length=20) == "8.8.8.0/24"


def test_ip_range_rejects_private_range():
    with pytest.raises(InvalidTargetError):
        validate_ip_range("10.0.0.0/24", max_ipv4_prefix_length=20)


def test_ip_address_rejects_private():
    with pytest.raises(InvalidTargetError):
        normalize_asset_value(AssetType.ip_address, "10.0.0.5", 20)


def test_ip_address_rejects_link_local():
    with pytest.raises(InvalidTargetError):
        normalize_asset_value(AssetType.ip_address, "169.254.1.1", 20)


def test_ip_range_exceeding_cap_is_rejected():
    with pytest.raises(InvalidTargetError):
        validate_ip_range("10.0.0.0/8", max_ipv4_prefix_length=20)


def test_url_rejects_non_http_scheme():
    with pytest.raises(InvalidTargetError):
        validate_url("ftp://example.com")


def test_url_normalizes_host_case():
    assert validate_url("https://Example.com/Path") == "https://example.com/Path"


# --- is_hostname_in_scope (Step 9.2 discovery scope boundary) -------------


def test_direct_subdomain_is_in_scope():
    assert is_hostname_in_scope("api.example.com", "example.com") is True


def test_multi_level_subdomain_is_in_scope():
    assert is_hostname_in_scope("foo.api.example.com", "api.example.com") is True


def test_seed_itself_is_in_scope():
    assert is_hostname_in_scope("example.com", "example.com") is True


def test_similarly_named_different_domain_is_rejected():
    """Not a subdomain -- a completely different registrable domain that
    merely shares a substring ("evil-example.com" is not under
    "example.com" at all).
    """
    assert is_hostname_in_scope("evil-example.com", "example.com") is False


def test_domain_as_suffix_of_attacker_domain_is_rejected():
    """The exact trap a naive string .endswith("example.com") check
    would fail: "example.com.evil.com" string-ends-with "example.com"
    but is a subdomain of "evil.com", not "example.com" at all.
    """
    assert is_hostname_in_scope("example.com.evil.com", "example.com") is False


def test_sibling_subdomain_is_rejected():
    """A subdomain of the same parent is not automatically in scope of
    a different, unrelated subdomain seed.
    """
    assert is_hostname_in_scope("mail.example.com", "api.example.com") is False


def test_scope_check_is_case_insensitive():
    assert is_hostname_in_scope("API.Example.COM", "example.com") is True


def test_scope_check_ignores_trailing_dot():
    assert is_hostname_in_scope("api.example.com.", "example.com.") is True
