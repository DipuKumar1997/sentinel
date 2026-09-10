"""Evidence storage abstraction.

Development uses the local filesystem under EVIDENCE_STORAGE_PATH.
Production should point EVIDENCE_STORAGE_BACKEND at an S3-compatible
bucket (e.g. MinIO) -- see docs/architecture.md for the swap-in plan.
Files are stored content-addressed by SHA-256 to make tampering evident
and to naturally deduplicate identical evidence.
"""
import hashlib
import os
import uuid
from pathlib import Path

from app.core.config import settings


class EvidenceStorageError(Exception):
    pass


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_case_dir(case_id: uuid.UUID) -> Path:
    """Builds a path scoped to a case, guarding against path traversal by
    only ever using a validated UUID as the directory name.
    """
    base = Path(settings.EVIDENCE_STORAGE_PATH).resolve()
    case_dir = (base / str(case_id)).resolve()
    if base not in case_dir.parents and case_dir != base:
        raise EvidenceStorageError("Path traversal detected in evidence storage path")
    case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir


def store_evidence_bytes(case_id: uuid.UUID, data: bytes, suffix: str = ".bin") -> tuple[str, str]:
    """Persists raw evidence bytes content-addressed by hash.

    Returns (storage_uri, sha256_hex_digest). The stored file is written
    read-only to reduce the risk of accidental mutation.
    """
    digest = compute_sha256(data)
    case_dir = _safe_case_dir(case_id)
    filename = f"{digest}{suffix}"
    file_path = case_dir / filename

    if not file_path.exists():
        with open(file_path, "wb") as fh:
            fh.write(data)
        os.chmod(file_path, 0o440)

    return str(file_path), digest


def read_evidence_bytes(storage_uri: str) -> bytes:
    path = Path(storage_uri)
    base = Path(settings.EVIDENCE_STORAGE_PATH).resolve()
    if base not in path.resolve().parents:
        raise EvidenceStorageError("Refusing to read evidence outside storage root")
    with open(path, "rb") as fh:
        return fh.read()
