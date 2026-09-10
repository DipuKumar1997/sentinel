import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class CreateMailboxRequest(BaseModel):
    address: str = Field(min_length=3, max_length=255, description="e.g. security@yourcompany.com")
    description: str | None = None
    imap_host: str = Field(min_length=1, max_length=255, description="e.g. imap.gmail.com")
    imap_port: int = 993
    imap_use_ssl: bool = True
    imap_username: str = Field(min_length=1, max_length=255)
    imap_password: str = Field(min_length=1, description="For Gmail: a 16-character App Password, not your account password.")
    imap_folder: str = Field(
        default="Sentinel_Intake",
        description=(
            "The IMAP folder/label to poll. Defaults to a dedicated 'Sentinel_Intake' "
            "label rather than INBOX, to avoid ingesting an entire pre-existing mailbox's "
            "history on first setup -- create this label in Gmail (or use a Gmail filter "
            "to auto-label forwarded mail into it) before registering the mailbox. "
            "Pass 'INBOX' explicitly if you want to poll the main inbox instead."
        ),
    )
    smtp_host: str | None = Field(
        default=None,
        description=(
            "SMTP host used to email the report back to whoever forwarded the message. "
            "Left blank, it's guessed from imap_host (imap.gmail.com -> smtp.gmail.com). "
            "Reuses the SAME imap_username/imap_password above -- no separate credential needed."
        ),
    )
    smtp_port: int = 587
    smtp_use_tls: bool = True
    notify_reporter: bool = Field(
        default=True,
        description="Email the HTML+PDF report back to the forwarding employee after each case is created.",
    )


class MailboxOut(BaseModel):
    id: uuid.UUID
    address: str
    description: str | None
    is_active: bool
    imap_host: str | None
    imap_port: int
    imap_username: str | None
    imap_folder: str
    is_polling_enabled: bool
    poll_interval_seconds: int
    last_polled_at: datetime | None
    last_poll_status: str | None
    last_poll_error: str | None
    smtp_host: str | None
    smtp_port: int
    notify_reporter: bool

    model_config = {"from_attributes": True}


class PollOutcomeOut(BaseModel):
    uid: int
    status: str
    case_id: uuid.UUID | None = None
    detail: str | None = None


class PollNowResponse(BaseModel):
    mailbox_id: uuid.UUID
    outcomes: list[PollOutcomeOut]
    message: str
