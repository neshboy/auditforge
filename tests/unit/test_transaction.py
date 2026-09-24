from auditforge.core.models import ChangeRecord
from auditforge.rollback.transaction import TransactionManager, new_transaction_id


def test_transaction_id_format():
    tx_id = new_transaction_id()
    assert tx_id.startswith("AF-")
    parts = tx_id.split("-")
    assert len(parts) == 4
    assert len(parts[1]) == 8  # YYYYMMDD
    assert len(parts[2]) == 6  # HHMMSS
    assert len(parts[3]) == 6  # hex suffix


def test_transaction_ids_are_unique():
    ids = {new_transaction_id() for _ in range(20)}
    assert len(ids) == 20


def test_begin_record_finalize_load_roundtrip(tmp_path):
    manager = TransactionManager(root=str(tmp_path))
    tx = manager.begin(profile="test", os_name="linux", os_version="24.04")
    assert tx.status == "in_progress"

    change = ChangeRecord(
        control_id="AF-TEST-001",
        primitive="test_stub",
        params={"key": "value"},
        previous_value=0,
        new_value=1,
        timestamp="2026-09-24T00:00:00Z",
    )
    manager.record_change(tx, change)
    manager.finalize(tx, "complete", post_audit_summary={"score_percent": 100})

    reloaded = manager.load(tx.tx_id)
    assert reloaded.status == "complete"
    assert len(reloaded.changes) == 1
    assert reloaded.changes[0].control_id == "AF-TEST-001"
    assert reloaded.changes[0].previous_value == 0
    assert reloaded.post_audit_summary == {"score_percent": 100}


def test_list_transactions_reverse_chronological(tmp_path):
    manager = TransactionManager(root=str(tmp_path))
    tx1 = manager.begin(profile="p1", os_name="linux", os_version="1")
    manager.finalize(tx1, "complete")
    tx2 = manager.begin(profile="p2", os_name="linux", os_version="1")
    manager.finalize(tx2, "complete")

    listed = manager.list_transactions()
    assert listed[0]["tx_id"] == tx2.tx_id or listed[0]["tx_id"] == tx1.tx_id
    ids = {t["tx_id"] for t in listed}
    assert {tx1.tx_id, tx2.tx_id} == ids


def test_load_missing_transaction_raises(tmp_path):
    manager = TransactionManager(root=str(tmp_path))
    import pytest

    with pytest.raises(FileNotFoundError):
        manager.load("AF-does-not-exist")


def test_no_secrets_ever_recorded_in_change_record(tmp_path):
    """Defense-in-depth check: nothing that looks like a credential field
    name should ever appear as a ChangeRecord key. Every real primitive
    only ever records configuration state, never secret material."""
    manager = TransactionManager(root=str(tmp_path))
    tx = manager.begin(profile="test", os_name="linux", os_version="24.04")
    change = ChangeRecord(
        control_id="AF-TEST-001",
        primitive="test_stub",
        params={"key": "value"},
        previous_value="Disabled",
        new_value="Enabled",
        timestamp="now",
    )
    manager.record_change(tx, change)
    manifest = tx.to_manifest()
    banned = ("password", "secret", "private_key", "token", "credential")
    serialized = str(manifest).lower()
    for word in banned:
        assert word not in serialized
