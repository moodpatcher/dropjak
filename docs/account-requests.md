# Account requests

**Date:** 2026-10-20

**Status:** implemented and committed as `c88b912`, deployed to the test VM
on 2026-10-20. The feature is disabled by default; the test portal has it
enabled.

This document describes the optional self-service account request feature.
The behavior below is the implementation contract; it is disabled by default.

## Behavior

Self-registration is controlled by an admin toggle and is **off by default**.
When it is off, the login page does not show the **Fiók kérése** (Request
account) button and `POST /api/register` returns `registration_disabled`.

When it is on, the login page shows the **Fiók kérése** button. The form asks
for a login name, password, password confirmation and email address. The
password confirmation exists only in the UI; the API receives one password
field.

A successful request creates a **pending** account with `pending=true`,
`enabled=false`, `rules=[]`, `totp_required=false`,
`must_change_password=false` and role `user`. No session or cookie is
created. A pending account cannot sign in, authorize network access, be
assigned rules or appear in admin user counts. It is a record waiting for an
admin decision, not an active account.

A sign-in attempt checks the password first. A correct password for a pending
account returns a distinct "awaiting admin approval" message; a wrong password
keeps the generic "invalid username or password" response. Neither creates a
session.

Pending state is fail-closed: a missing `pending` field means `false`, while
any malformed value (for example a string or a number) parses as `true`. A
corrupted record therefore stays pending instead of becoming active.

## Data model

User records live in `users.json` in the `hatarvedelem-state` volume
(`/var/lib/hatarvedelem/users.json`, mode `0600`). Registration adds two
stored fields:

| Field | Type | Meaning |
|---|---|---|
| `pending` | boolean | Created by a public request and not yet approved. Missing means `false`; a malformed value parses as `true`. |
| `email` | string | Contact address from the request. Trimmed, lowercased, at most 254 characters. Never returned to the requester and never logged. |

The password uses the existing PBKDF2-HMAC-SHA256 record (per-user salt,
iteration count and hash); the plaintext is never stored. Other fields are the
normal user fields with the pending values above.

The admin user representation (`public()`) exposes both `pending` and `email`.
Unauthenticated payloads never expose either. Password material, TOTP secrets
and recovery-code hashes remain hidden as before.

## API endpoints

| Endpoint / action | Purpose |
|---|---|
| `POST /api/register` | Public registration. Creates a pending account and returns a generic confirmation, with no `Set-Cookie`. |
| `POST /api/admin/users`, action `approve` | Sets `pending=false`, `enabled=true`, keeps password/rules/email, audits `registration_approved`. |
| `POST /api/admin/users`, action `reject` | Removes the record, audits `registration_rejected`. A user who is not pending cannot be rejected. |
| `POST /api/admin/settings`, action `registration_enabled` | Admin toggle; takes `{"enabled": true}` or `{"enabled": false}`. |
| `GET /api/status` | The unauthenticated response exposes only the `registration_enabled` boolean, not the other firewall settings. |

Registration is JSON-only, same-origin (the `Origin` header must match the
portal host when present) and IPv4-only. It is captcha-gated with the same
mechanism as login: Turnstile when configured, otherwise the proof-of-work
challenge from `/api/challenge`. It has a dedicated rate limit of 3 requests
per 10 minutes per source IP, separate from the login rate limit.

The request accepts either spelling for the main fields: `user` or `name`, and
`pass` or `password`. The `captcha` field is a JSON object in the same format
as `/api/login` (a solved proof-of-work payload or a Turnstile token).

### Request example

```json
{
  "user": "alice",
  "pass": "correct horse battery staple",
  "email": "alice@example.com",
  "captcha": {"challenge": "...", "salt": "...", "algorithm": "SHA-256",
              "difficulty": 20, "expires": 1760000000, "signature": "...",
              "number": 123456}
}
```

### Response examples

Success is a generic confirmation that does not reveal whether a username or
email was already present. The message text below is illustrative.

```json
{"ok": true, "message": "Kérelmedet rögzítettük. Az admin jóváhagyása után beléphetsz."}
```

| Situation | HTTP | Response |
|---|---|---|
| Registration disabled | `403` | `{"ok": false, "error": "...", "code": "registration_disabled"}` |
| Username already exists | `409` | `{"ok": false, "error": "...", "code": "username_taken"}` |
| Captcha failure | `403` | `{"ok": false, "error": "Captcha: ..."}` |
| Rate limit exceeded | `429` | `{"ok": false, "error": "..."}` |
| Invalid email | `400` | `{"ok": false, "error": "..."}` |

Email handling: the address is trimmed, lowercased, limited to 254 characters
and checked with a basic `name@domain.tld` pattern. Duplicate email addresses
are allowed on purpose. This avoids revealing whether an address is already
registered; email is only a contact record, not an identity or recovery
mechanism.

Audit behavior: `registration_requested` contains the username only, never the
email or password. Approval and rejection write `registration_approved` and
`registration_rejected`. A request is not an authentication event.

## Settings

The flag is stored as `registration_enabled` (boolean, default `false`) in
`firewall-settings.json` in the state volume, validated by
`settings_store.validate_state` with the other settings. If the file is
invalid, the fail-closed fallback applies and registration stays off.

The admin Settings API changes it with:

```json
{"action": "registration_enabled", "enabled": true}
```

This action is portal-only: it is validated and committed to
`firewall-settings.json` without calling nftables or `apply_settings`. It does
not reload firewall rules and does not affect existing grants. The admin
**Settings** tab shows the option as the **Fiókkérelmek** checkbox; the login
page shows the **Fiók kérése** button only while the flag is enabled.

## Admin UI

The **Admin → Users** tab has a separate pending section for accounts created
through the public form. A pending row shows the login name and the stored
email, with **approve** and **reject** actions.

- **Approve** activates the account: `pending=false`, `enabled=true`. The
  password, the empty rule list and the email are kept; the action is audited
  as `registration_approved`.
- **Reject** deletes the record and audits `registration_rejected`.

Approval does **not** grant rules or group memberships. The account is a
normal, enabled `user` with no rules; the admin assigns them later. Pending
accounts never count as admins, so the last-active-admin guard is unaffected.

## Security notes

- No email is sent. The address is stored only; there is no verification
  message, delivery attempt or recovery flow. Email and passwords are never
  included in audit entries or logs.
- No session or cookie exists before approval. Pending accounts cannot log in,
  authorize access, receive rules or hold group memberships.
- Pending parsing is fail-closed: a missing flag is inactive (`false`), but a
  malformed value is treated as pending (`true`).
- `users.json` is written atomically with mode `0600` in the state volume.
  Email addresses are sensitive personal data; protect the volume and every
  backup that contains it.
- Duplicate emails are accepted to avoid confirming whether an address is
  already on file. Usernames must still be unique, so a duplicate username is
  reported as `username_taken`.
- Captcha and the dedicated rate limit apply before an account is created.
  Registration does not weaken TOTP 2FA, fail2ban, MAC binding or the
  two-phase access flow.
- Approval does not grant network access by itself. The user must still sign
  in, choose a rule and TTL, and authorize the grant; grants remain bound to
  the client IP and MAC address.

## Limitations and future ideas

- **No email verification, delivery or notification.** The address is not
  verified and cannot be used for password recovery; new requests appear only
  in the Users tab pending section.
- **No invitation or allowlist flow.** While the toggle is on, any IPv4 client
  that can reach the portal and solve the captcha can request an account.
- **No cancellation, expiry or bulk operations.** Pending records stay until
  an admin approves or rejects them, one at a time.
