"""IMAP mailbox polling: turns "employee forwards suspicious mail to
security@company.com" into cases automatically.
"""
from __future__ import annotations

import hashlib
import imaplib
import json
import logging
import re
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.case import Mailbox, MailboxProcessedMessage, Note
from app.services import email_notification, ingestion, report_generator
from app.services.mailbox_service import MailboxError, get_decrypted_password

logger = logging.getLogger(__name__)

_FORWARD_MARKERS = (
    "---------- forwarded message ---------",
    "-----original message-----",
    "begin forwarded message:",
)
_FROM_LINE_RE = re.compile(r"^\s*from:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


@dataclass
class ForwardExtraction:
    analysis_bytes: bytes
    forward_type: str
    outer_message_id: str | None
    outer_from: str | None
    claimed_original_sender: str | None = None


@dataclass
class PollOutcome:
    uid: int
    status: str
    case_id: uuid.UUID | None = None
    detail: str | None = None


def _extract_forward_target(raw_bytes: bytes) -> ForwardExtraction:
    outer = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    outer_message_id = outer.get("Message-ID")
    outer_from = outer.get("From")

    if outer.is_multipart():
        for part in outer.walk():
            if part.get_content_type() == "message/rfc822":
                nested = part.get_payload(0)
                try:
                    nested_bytes = nested.as_bytes()
                except Exception:
                    continue
                return ForwardExtraction(
                    analysis_bytes=nested_bytes,
                    forward_type="attachment",
                    outer_message_id=outer_message_id,
                    outer_from=outer_from,
                )

    body_text = ""
    try:
        if outer.is_multipart():
            for part in outer.walk():
                if part.get_content_type() == "text/plain":
                    body_text = part.get_content()
                    break
        else:
            body_text = outer.get_content()
    except Exception:
        body_text = ""

    body_lower = (body_text or "").lower()
    claimed_sender = None
    forward_type = "direct"
    for marker in _FORWARD_MARKERS:
        idx = body_lower.find(marker)
        if idx != -1:
            forward_type = "inline"
            window = body_text[idx: idx + 600]
            match = _FROM_LINE_RE.search(window)
            if match:
                claimed_sender = match.group(1).strip()
            break

    return ForwardExtraction(
        analysis_bytes=raw_bytes,
        forward_type=forward_type,
        outer_message_id=outer_message_id,
        outer_from=outer_from,
        claimed_original_sender=claimed_sender,
    )


def _connect(mailbox: Mailbox) -> imaplib.IMAP4:
    if mailbox.imap_use_ssl:
        conn = imaplib.IMAP4_SSL(mailbox.imap_host, mailbox.imap_port)
    else:
        conn = imaplib.IMAP4(mailbox.imap_host, mailbox.imap_port)
    password = get_decrypted_password(mailbox)
    conn.login(mailbox.imap_username, password)
    return conn


def _parse_imap_status(status_response) -> tuple[int | None, int | None]:
    """Extracts both UIDVALIDITY and UIDNEXT from the IMAP status response."""
    if not status_response:
        return None, None
    text = status_response[0].decode(errors="replace") if isinstance(status_response[0], bytes) else str(status_response[0])

    val_match = re.search(r"UIDVALIDITY (\d+)", text)
    nxt_match = re.search(r"UIDNEXT (\d+)", text)

    uidvalidity = int(val_match.group(1)) if val_match else None
    uidnext = int(nxt_match.group(1)) if nxt_match else None

    return uidvalidity, uidnext


async def _process_one_message(
    db: AsyncSession, *, mailbox: Mailbox, uid: int, raw_bytes: bytes
) -> PollOutcome:
    existing = await db.scalar(
        select(MailboxProcessedMessage).where(
            MailboxProcessedMessage.mailbox_id == mailbox.id,
            MailboxProcessedMessage.imap_uid == uid,
        )
    )
    if existing is not None:
        return PollOutcome(uid=uid, status="skipped_duplicate", detail="Already processed (by UID).")

    extraction = _extract_forward_target(raw_bytes)
    evidence_sha256 = hashlib.sha256(extraction.analysis_bytes).hexdigest()

    duplicate_by_hash = await db.scalar(
        select(MailboxProcessedMessage).where(
            MailboxProcessedMessage.mailbox_id == mailbox.id,
            MailboxProcessedMessage.evidence_sha256 == evidence_sha256,
        )
    )
    if duplicate_by_hash is not None:
        db.add(
            MailboxProcessedMessage(
                mailbox_id=mailbox.id, imap_uid=uid, evidence_sha256=evidence_sha256,
                status="skipped_duplicate", detail="Identical content already processed (by evidence hash).",
            )
        )
        await db.commit()
        return PollOutcome(uid=uid, status="skipped_duplicate", detail="Duplicate content.")

    try:
        case, email_message, risk_score = await ingestion.ingest_email_and_create_case(
            db,
            organization_id=mailbox.organization_id,
            reporter_user_id=mailbox.service_user_id,
            raw_bytes=extraction.analysis_bytes,
            original_filename=f"forwarded-{mailbox.address}-uid{uid}.eml",
        )
    except ingestion.IngestionError as exc:
        db.add(
            MailboxProcessedMessage(
                mailbox_id=mailbox.id, imap_uid=uid, evidence_sha256=evidence_sha256,
                status="error", detail=f"Ingestion failed: {exc.message}",
            )
        )
        await db.commit()
        return PollOutcome(uid=uid, status="error", detail=exc.message)

    forward_note_lines = [
        f"Received via mailbox forwarding ({mailbox.address}).",
        f"Forward type: {extraction.forward_type}.",
    ]
    if extraction.outer_from:
        forward_note_lines.append(f"Forwarding envelope From: {extraction.outer_from}")
    if extraction.forward_type == "attachment":
        forward_note_lines.append(
            "Original message was extracted from a message/rfc822 attachment "
            "(the analyzed content above is the ORIGINAL message, not the forwarding envelope)."
        )
    elif extraction.claimed_original_sender:
        forward_note_lines.append(
            f"Body text claims original sender was: {extraction.claimed_original_sender} "
            "(UNVERIFIED -- extracted from quoted message text, not authenticated, not used in scoring)."
        )

    db.add(
        Note(
            case_id=case.id,
            author_user_id=mailbox.service_user_id,
            body="\n".join(forward_note_lines),
        )
    )
    db.add(
        MailboxProcessedMessage(
            mailbox_id=mailbox.id,
            imap_uid=uid,
            message_id_header=extraction.outer_message_id,
            evidence_sha256=evidence_sha256,
            case_id=case.id,
            status="created",
            detail=json.dumps({
                "forward_type": extraction.forward_type,
                "outer_from": extraction.outer_from,
                "claimed_original_sender": extraction.claimed_original_sender,
                "risk_score": risk_score.score,
                "classification": risk_score.classification,
            }),
        )
    )
    await db.commit()

    # --- Send the report back to whoever forwarded this email ---
    # Best-effort: notification failure (bad SMTP creds, network issue,
    # provider rate limit) must never undo or hide the successfully
    # created case -- only the notification attempt itself is recorded.
    notification_detail = None
    if extraction.outer_from:
        try:
            html_report, pdf_report = await report_generator.generate_both_formats(db, case=case)
            result = email_notification.send_report_notification(
                mailbox,
                to_header_value=extraction.outer_from,
                case_number=case.case_number,
                risk_score=risk_score.score,
                classification=risk_score.classification,
                html_report=html_report,
                pdf_report=pdf_report,
            )
            notification_detail = {
                "sent": result.sent,
                "recipient": result.recipient,
                "error_detail": result.error_detail,
            }
            if not result.sent:
                logger.warning(
                    "Report notification not sent for case %s: %s",
                    case.case_number, result.error_detail,
                )
        except Exception:
            logger.exception("Unexpected error sending report notification for case %s", case.case_number)
            notification_detail = {"sent": False, "error_detail": "Unexpected error -- see server logs."}

    if notification_detail is not None:
        db.add(
            Note(
                case_id=case.id,
                author_user_id=mailbox.service_user_id,
                body=(
                    f"Report notification {'sent to' if notification_detail['sent'] else 'NOT sent to'} "
                    f"{notification_detail.get('recipient') or extraction.outer_from}"
                    + (f": {notification_detail['error_detail']}" if notification_detail.get("error_detail") else ".")
                ),
            )
        )
        await db.commit()

    return PollOutcome(uid=uid, status="created", case_id=case.id)


async def poll_mailbox(db: AsyncSession, mailbox: Mailbox) -> list[PollOutcome]:
    """Polls one mailbox for new messages since the last poll."""
    if not mailbox.is_polling_enabled or not mailbox.is_active:
        return []
    if not mailbox.imap_host or not mailbox.imap_username or not mailbox.encrypted_password:
        mailbox.last_poll_status = "error"
        mailbox.last_poll_error = "Mailbox has no IMAP credentials configured."
        await db.commit()
        return []

    try:
        conn = _connect(mailbox)
    except (MailboxError, OSError, imaplib.IMAP4.error) as exc:
        mailbox.last_poll_status = "error"
        mailbox.last_poll_error = f"Connection/login failed: {exc}"
        mailbox.last_polled_at = datetime.now(timezone.utc)
        await db.commit()
        return []

    outcomes: list[PollOutcome] = []

    # --- CRITICAL FIX: Cache IDs and state to survive rollbacks ---
    mailbox_id = mailbox.id
    current_last_seen_uid = mailbox.last_seen_uid

    try:
        status, sv_data = conn.status(mailbox.imap_folder, "(UIDVALIDITY UIDNEXT)")
        current_uidvalidity, current_uidnext = _parse_imap_status(sv_data) if status == "OK" else (None, None)

        if current_uidvalidity is not None and mailbox.uid_validity is not None and current_uidvalidity != mailbox.uid_validity:
            current_last_seen_uid = 0

        if current_uidvalidity is not None:
            mailbox.uid_validity = current_uidvalidity

        # --- SMART BOOTSTRAP LOGIC ---
        # If the DB was just wiped/created (current_last_seen_uid == 0), don't process
        # the entire historical backlog. Fast-forward the bookmark to the end of the inbox.
        if current_last_seen_uid == 0 and current_uidnext is not None and current_uidnext > 1:
            current_last_seen_uid = current_uidnext - 2
            logger.info(f"Fresh database detected. Fast-forwarding {mailbox.address} to UID {current_last_seen_uid}")

        status, _ = conn.select(mailbox.imap_folder, readonly=False)
        if status != "OK":
            raise imaplib.IMAP4.error(f"Could not select folder {mailbox.imap_folder!r}")

        search_from = current_last_seen_uid + 1
        status, uid_data = conn.uid("search", None, f"(UID {search_from}:*)")
        raw_uids = uid_data[0].split() if status == "OK" and uid_data and uid_data[0] else []
        uids = sorted({int(u) for u in raw_uids if int(u) >= search_from})

        for uid in uids:
            try:
                status, msg_data = conn.uid("fetch", str(uid), "(RFC822)")
                if status != "OK" or not msg_data or msg_data[0] is None:
                    outcomes.append(PollOutcome(uid=uid, status="error", detail="IMAP fetch returned no data."))
                    continue

                raw_bytes = msg_data[0][1]
                outcome = await _process_one_message(db, mailbox=mailbox, uid=uid, raw_bytes=raw_bytes)
                outcomes.append(outcome)

                if outcome.status in ("created", "skipped_duplicate"):
                    current_last_seen_uid = max(current_last_seen_uid, uid)
                    try:
                        conn.uid("store", str(uid), "+FLAGS", "(\\Seen)")
                    except imaplib.IMAP4.error:
                        pass

            except Exception as exc:
                # Rollback the poisoned transaction
                await db.rollback()
                logger.exception(f"Unexpected error processing uid {uid}")
                outcomes.append(
                    PollOutcome(uid=uid, status="error", detail=f"{type(exc).__name__}: {exc}")
                )

                # CRITICAL FIX: The rollback expired the 'mailbox' object.
                # Re-fetch it so the next iteration doesn't crash with MissingGreenlet.
                mailbox = await db.get(Mailbox, mailbox_id)

        # Apply the final successful state
        mailbox.last_seen_uid = current_last_seen_uid
        mailbox.last_poll_status = "ok"
        mailbox.last_poll_error = None
        mailbox.last_polled_at = datetime.now(timezone.utc)
        await db.commit()

    except Exception as exc:
        mailbox.last_poll_status = "error"
        mailbox.last_poll_error = str(exc)
        mailbox.last_polled_at = datetime.now(timezone.utc)
        await db.commit()
    finally:
        try:
            conn.logout()
        except Exception:
            pass

    return outcomes


async def poll_all_active_mailboxes(db: AsyncSession) -> dict[uuid.UUID, list[PollOutcome]]:
    mailboxes = (
        await db.execute(select(Mailbox).where(Mailbox.is_active == True, Mailbox.is_polling_enabled == True))  # noqa: E712
    ).scalars().all()

    results: dict[uuid.UUID, list[PollOutcome]] = {}
    for mailbox in mailboxes:
        results[mailbox.id] = await poll_mailbox(db, mailbox)
    return results
