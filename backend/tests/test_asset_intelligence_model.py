"""Step 8.1: schema-level verification for the Asset Intelligence domain
model. No API/route exists yet for Service/Certificate (a later Step 8
sub-step), so these are direct-ORM tests against the `db` fixture rather
than HTTP tests — same style already used for model-level concerns
elsewhere in this suite.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.enums import AssetSource, LifecycleStatus
from app.models import Asset, Certificate, Service


def _create_asset(client, headers, value="example.com"):
    resp = client.post("/assets", json={"asset_type": "domain", "value": value}, headers=headers)
    assert resp.status_code == 201
    return resp.json()["id"]


def test_manually_created_asset_gets_intelligence_defaults(client, register_user, db):
    headers = register_user()
    asset_id = _create_asset(client, headers)

    asset = db.query(Asset).filter(Asset.id == asset_id).one()
    assert asset.status == LifecycleStatus.active
    assert asset.source == AssetSource.manual
    assert asset.confidence == 1.0
    assert asset.environment is None
    assert asset.criticality is None
    assert asset.owner is None
    assert asset.tags == []
    assert asset.first_seen is not None
    assert asset.last_seen is not None


def test_service_dedup_key_rejects_duplicate_port_protocol(client, register_user, db):
    headers = register_user()
    asset_id = _create_asset(client, headers)
    now = datetime.now(timezone.utc)

    db.add(Service(asset_id=asset_id, port=443, protocol="tcp", first_seen=now, last_seen=now))
    db.commit()

    db.add(Service(asset_id=asset_id, port=443, protocol="tcp", first_seen=now, last_seen=now))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_service_defaults_and_relationship(client, register_user, db):
    headers = register_user()
    asset_id = _create_asset(client, headers)
    now = datetime.now(timezone.utc)

    service = Service(asset_id=asset_id, port=22, protocol="tcp", first_seen=now, last_seen=now)
    db.add(service)
    db.commit()
    db.refresh(service)

    assert service.status == LifecycleStatus.active
    assert service.source == AssetSource.manual
    assert service.confidence == 1.0

    asset = db.query(Asset).filter(Asset.id == asset_id).one()
    assert len(asset.services) == 1
    assert asset.services[0].port == 22


def test_certificate_dedup_key_rejects_duplicate_hostname_port(client, register_user, db):
    headers = register_user()
    asset_id = _create_asset(client, headers)
    now = datetime.now(timezone.utc)

    db.add(Certificate(asset_id=asset_id, hostname="example.com", port=443, first_seen=now, last_seen=now))
    db.commit()

    db.add(Certificate(asset_id=asset_id, hostname="example.com", port=443, first_seen=now, last_seen=now))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_certificate_defaults_and_relationship(client, register_user, db):
    headers = register_user()
    asset_id = _create_asset(client, headers)
    now = datetime.now(timezone.utc)

    cert = Certificate(asset_id=asset_id, hostname="example.com", port=443, first_seen=now, last_seen=now)
    db.add(cert)
    db.commit()
    db.refresh(cert)

    assert cert.status == LifecycleStatus.active
    assert cert.source == AssetSource.manual
    assert cert.is_expired is False
    assert cert.is_self_signed is False

    asset = db.query(Asset).filter(Asset.id == asset_id).one()
    assert len(asset.certificates) == 1
    assert asset.certificates[0].hostname == "example.com"


def test_deleting_asset_cascades_to_services_and_certificates(client, register_user, db):
    headers = register_user()
    asset_id = _create_asset(client, headers)
    now = datetime.now(timezone.utc)

    db.add(Service(asset_id=asset_id, port=80, protocol="tcp", first_seen=now, last_seen=now))
    db.add(Certificate(asset_id=asset_id, hostname="example.com", port=443, first_seen=now, last_seen=now))
    db.commit()

    asset = db.query(Asset).filter(Asset.id == asset_id).one()
    db.delete(asset)
    db.commit()

    assert db.query(Service).count() == 0
    assert db.query(Certificate).count() == 0
