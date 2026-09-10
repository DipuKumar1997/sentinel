# Setting Up Real Mailbox Forwarding (Gmail)

This walks through making `forward suspicious email -> case appears
automatically` work against a real Gmail inbox. No Google Cloud
Console project, no OAuth consent screen, no Gmail API enablement
needed -- this uses plain **IMAP with an App Password**, a standard
feature of every Gmail account, which is why it works identically for
Gmail, Google Workspace, Outlook/Office365, or any other IMAP-capable
provider.

(If you specifically want the Gmail API/OAuth2 path instead of IMAP --
e.g. for finer-grained scopes or push notifications instead of
polling -- that's a larger undertaking tracked in `NEXT_STEPS.md`, not
implemented here.)

## 1. Enable IMAP on the Gmail account

1. Open Gmail → **Settings (gear icon) → See all settings**.
2. Go to the **Forwarding and POP/IMAP** tab.
3. Under "IMAP access," select **Enable IMAP**.
4. Save changes.

## 2. Turn on 2-Step Verification (required for App Passwords)

App Passwords only exist once 2-Step Verification is on.

1. Go to [myaccount.google.com/security](https://myaccount.google.com/security).
2. Under "How you sign in to Google," enable **2-Step Verification** if
   it isn't already.

## 3. Generate an App Password

1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
   (this link only works once 2-Step Verification is on).
2. Under "App name," type something like `SentinelMail` and click
   **Create**.
3. Google shows a **16-character password** (spaces don't matter --
   copy it with or without them). **This is what you give
   SentinelMail, not your real Gmail password.**
4. Keep this tab open or copy the password somewhere safe -- Google
   only shows it once.

## 4. Register the mailbox with SentinelMail

You need an `org_admin` account first (the first person to register
for your organization becomes admin automatically -- see README.md).
Then:

```bash
# 1. Log in to get a JWT
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "your-admin@yourcompany.com", "password": "your-password"}'
# -> {"access_token": "...", ...}

# 2. Register the mailbox
curl -X POST http://localhost:8000/api/v1/mailboxes \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "address": "dk95074450@gmail.com",
    "description": "Security intake mailbox",
    "imap_host": "imap.gmail.com",
    "imap_port": 993,
    "imap_use_ssl": true,
    "imap_username": "dk95074450@gmail.com",
    "imap_password": "abcd efgh ijkl mnop",
    "imap_folder": "INBOX"
  }'
```

Replace `imap_password` with the App Password from step 3 (spaces are
fine either way -- IMAP libraries strip them, and so does Gmail's own
verification of it). The response confirms the mailbox was created
with `"is_polling_enabled": true` and never echoes the password back.

## 5. Test it immediately (don't wait for the schedule)

```bash
curl -X POST http://localhost:8000/api/v1/mailboxes/<mailbox_id>/poll-now \
  -H "Authorization: Bearer <access_token>"
```

Now forward (or have someone forward) a suspicious email to
`dk95074450@gmail.com`, then run the `poll-now` call again. You should
see:

```json
{
  "mailbox_id": "...",
  "outcomes": [{"uid": 1, "status": "created", "case_id": "..."}],
  "message": "Poll succeeded -- 1 new case(s) created out of 1 message(s) seen."
}
```

Fetch the case exactly like any other:
```bash
curl http://localhost:8000/api/v1/cases/<case_id>/risk-score -H "Authorization: Bearer <access_token>"
curl http://localhost:8000/api/v1/cases/<case_id>/findings -H "Authorization: Bearer <access_token>"
```

## 6. Let the scheduler take over

Once `poll-now` works, you don't need to call it manually again --
`docker-compose.yml`'s `worker` service runs an embedded Celery beat
scheduler that polls every active mailbox every 2 minutes (see
`app/workers/celery_app.py`'s `beat_schedule`). Just forward mail to
the inbox and check back in a couple of minutes.

## What happens to the forwarded email, exactly

Two real-world forwarding styles are both handled correctly (see
`app/services/mailbox_polling.py::_extract_forward_target`):

- **"Forward as attachment"** (e.g. Gmail → message menu → "Forward as
  attachment"): the original email arrives as a genuine `message/rfc822`
  MIME part. SentinelMail extracts and analyzes the ORIGINAL message
  (with its own real SPF/DKIM/DMARC headers), not your forwarding
  envelope -- your forwarding note is preserved as a case Note instead.
- **Plain "Forward"** (Gmail's default -- quotes the original inline in
  the body with a `---------- Forwarded message ---------` marker):
  there's no separate object to extract, so the delivered message
  (whose body/URLs/attachments ARE the actual threat surface) is
  analyzed directly. SentinelMail also makes a best-effort, clearly
  labeled note of what the quoted text *claims* the original sender
  was -- this is never authenticated and never used in scoring, purely
  informational context for whoever reviews the case.

In both cases, **your identity as the forwarding employee is never
confused with the original (possibly malicious) sender's claimed
identity** -- see `docs/architecture.md` section 3 for why that
separation is a hard rule throughout this codebase.

## Troubleshooting

- **`poll-now` returns `"Poll failed: Connection/login failed: ..."`**
  → Almost always means either IMAP isn't enabled (step 1) or you're
  using your real password instead of the App Password (step 3).
- **Duplicate cases from the same email** → Shouldn't happen; IMAP UIDs
  and a secondary evidence-hash check both guard against reprocessing
  (see `MailboxProcessedMessage` in `app/models/case.py`). If you do
  see it, please check `GET /mailboxes` for `last_poll_error` and file
  it as a bug.
- **Messages aren't being picked up at all** → Check
  `GET /mailboxes` for `last_poll_status`/`last_poll_error` on that
  mailbox first.
