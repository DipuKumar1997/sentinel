"""Evidence-integrity hash chain ("blockchain" in the sense the project
brief asks for: a cryptographic hash chain for tamper-evidence, not a
distributed consensus network -- see app/models/ioc.py::BlockchainAnchor
for why that distinction is stated plainly rather than oversold).

Each anchor commits to: the previous anchor's hash (within the same
organization), the case ID, the evidence SHA-256, the event type, and a
timestamp. Because each entry's hash depends on the previous entry's
hash, altering or deleting any historical anchor changes every
subsequent computed_hash, making tampering with the chain's history
detectable -- exactly the property a blockchain provides, achieved here
with a simple, auditable, dependency-free hash chain instead of mining/
consensus (which would be pointless for a single-organization,
single-writer ledger like this one).

No email content, bodies, subjects, or attachments are ever anchored --
only hashes already computed elsewhere (evidence_hashes, report hashes).
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ioc import BlockchainAnchor

_GENESIS_HASH = "0" * 64


async def _get_latest_hash(db: AsyncSession, organization_id: uuid.UUID) -> str:
    latest = await db.scalar(
        select(BlockchainAnchor)
        .where(BlockchainAnchor.organization_id == organization_id)
        .order_by(BlockchainAnchor.created_at.desc())
    )
    return latest.computed_hash if latest else _GENESIS_HASH


def _compute_hash(
    *, previous_hash: str, organization_id: uuid.UUID, case_id: uuid.UUID | None,
    event_type: str, evidence_sha256: str | None, report_sha256: str | None, hash_timestamp: float,
) -> str:
    payload = "|".join([
        previous_hash,
        str(organization_id),
        str(case_id) if case_id else "",
        event_type,
        evidence_sha256 or "",
        report_sha256 or "",
        repr(hash_timestamp),
    ])
    return hashlib.sha256(payload.encode()).hexdigest()


async def anchor_event(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    case_id: uuid.UUID | None,
    event_type: str,
    evidence_sha256: str | None = None,
    report_sha256: str | None = None,
) -> BlockchainAnchor:
    """Appends a new anchor to the organization's hash chain. Must be
    called within the same DB session/transaction as the event it's
    anchoring, so the anchor and the event it certifies are atomic.
    """
    previous_hash = await _get_latest_hash(db, organization_id)
    timestamp = datetime.now(timezone.utc)
    hash_timestamp = timestamp.timestamp()
    computed_hash = _compute_hash(
        previous_hash=previous_hash, organization_id=organization_id, case_id=case_id,
        event_type=event_type, evidence_sha256=evidence_sha256, report_sha256=report_sha256,
        hash_timestamp=hash_timestamp,
    )
    anchor = BlockchainAnchor(
        id=uuid.uuid4(),
        created_at=timestamp,
        organization_id=organization_id,
        case_id=case_id,
        event_type=event_type,
        evidence_sha256=evidence_sha256,
        report_sha256=report_sha256,
        previous_hash=previous_hash,
        computed_hash=computed_hash,
        hash_timestamp=hash_timestamp,
    )
    db.add(anchor)
    await db.flush()
    return anchor


async def verify_chain_integrity(db: AsyncSession, organization_id: uuid.UUID) -> dict:
    """Recomputes every anchor's hash from its recorded inputs and
    compares against what's stored, in order, detecting any tampering
    anywhere in the organization's chain history.
    """
    anchors = (
        await db.execute(
            select(BlockchainAnchor)
            .where(BlockchainAnchor.organization_id == organization_id)
            .order_by(BlockchainAnchor.created_at.asc())
        )
    ).scalars().all()

    if not anchors:
        return {"verified": True, "anchor_count": 0, "message": "No anchors exist yet for this organization."}

    expected_previous = _GENESIS_HASH
    for anchor in anchors:
        if anchor.previous_hash != expected_previous:
            return {
                "verified": False,
                "anchor_count": len(anchors),
                "message": (
                    f"Chain broken at anchor {anchor.id}: expected previous_hash "
                    f"'{expected_previous}' but found '{anchor.previous_hash}'."
                ),
                "failed_anchor_id": str(anchor.id),
            }
        recomputed = _compute_hash(
            previous_hash=anchor.previous_hash, organization_id=anchor.organization_id, case_id=anchor.case_id,
            event_type=anchor.event_type, evidence_sha256=anchor.evidence_sha256,
            report_sha256=anchor.report_sha256, hash_timestamp=anchor.hash_timestamp,
        )
        if recomputed != anchor.computed_hash:
            return {
                "verified": False,
                "anchor_count": len(anchors),
                "message": f"Anchor {anchor.id}'s stored hash does not match its recomputed hash -- data was altered.",
                "failed_anchor_id": str(anchor.id),
            }
        expected_previous = anchor.computed_hash

    return {"verified": True, "anchor_count": len(anchors), "message": "All anchors verified -- chain is intact."}


async def verify_case_evidence(db: AsyncSession, *, case_id: uuid.UUID, current_evidence_sha256: str) -> dict:
    """Compares the CURRENT sha256 of a case's stored evidence file
    against what was anchored at ingestion time -- the concrete,
    per-case "has this evidence been tampered with" check.
    """
    anchor = await db.scalar(
        select(BlockchainAnchor)
        .where(BlockchainAnchor.case_id == case_id, BlockchainAnchor.event_type == "case_created")
        .order_by(BlockchainAnchor.created_at.asc())
    )
    if anchor is None:
        return {"verified": False, "message": "No blockchain anchor found for this case."}
    if anchor.evidence_sha256 == current_evidence_sha256:
        return {
            "verified": True,
            "message": "Current evidence hash matches the anchored hash from ingestion time.",
            "anchored_hash": anchor.evidence_sha256,
            "anchored_at": anchor.created_at.isoformat(),
        }
    return {
        "verified": False,
        "message": "MISMATCH: current evidence hash does not match the anchored hash. Evidence may have been altered.",
        "anchored_hash": anchor.evidence_sha256,
        "current_hash": current_evidence_sha256,
    }
