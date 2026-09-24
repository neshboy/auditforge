"""Rollback executor: replays a transaction's ChangeRecords in reverse and
asks each primitive to restore the recorded previous_value.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Optional

from auditforge.core import registry
from auditforge.core.bootstrap import load_primitives_for
from auditforge.core.models import OperatingSystem
from auditforge.rollback.transaction import Transaction, TransactionManager


@dataclasses.dataclass
class RollbackItemResult:
    control_id: str
    primitive: str
    restored: bool
    message: str = ""


@dataclasses.dataclass
class RollbackReport:
    tx_id: str
    items: list = dataclasses.field(default_factory=list)  # list[RollbackItemResult]

    @property
    def all_restored(self) -> bool:
        return all(i.restored for i in self.items)


def rollback_transaction(tx_id: str, manager: Optional[TransactionManager] = None) -> RollbackReport:
    manager = manager or TransactionManager()
    tx: Transaction = manager.load(tx_id)

    os_name = _os_enum_from_name(tx.os_name)
    load_primitives_for(os_name)

    report = RollbackReport(tx_id=tx_id)
    for change in reversed(tx.changes):
        try:
            primitive = registry.get(change.primitive)
            restored = primitive.rollback(change.params, change)
            report.items.append(
                RollbackItemResult(
                    control_id=change.control_id,
                    primitive=change.primitive,
                    restored=bool(restored),
                    message="restored previous value" if restored else "rollback returned False",
                )
            )
        except Exception as exc:  # noqa: BLE001 - surface every failure, keep going
            report.items.append(
                RollbackItemResult(
                    control_id=change.control_id,
                    primitive=change.primitive,
                    restored=False,
                    message=f"error: {exc}",
                )
            )

    tx.status = "rolled_back" if report.all_restored else "partial"
    tx.finished_at = datetime.now(timezone.utc).isoformat()
    manager._save(tx)
    return report


def _os_enum_from_name(os_name: str) -> OperatingSystem:
    lowered = (os_name or "").lower()
    if "win" in lowered:
        return OperatingSystem.WINDOWS
    if "mac" in lowered or "darwin" in lowered:
        return OperatingSystem.MACOS
    return OperatingSystem.LINUX
