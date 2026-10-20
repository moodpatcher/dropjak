# TOTP two-factor authentication

**Date:** 2026-10-20

**Status:** implemented and committed as `8f46da3`, deployed to the test VM
on 2026-10-20. The QR-code enrollment addition described below is not
committed or deployed yet.

This document is the technical reference for the optional per-user TOTP 2FA
in the portal. It describes the behavior, state, API surface and limitations.
It does not contain secrets, ticket values or recovery codes.

## Behavior

TOTP 2FA is opt-in per user. An admin sets `totp_required` when creating or
editing a user; new users default to `false`. An enrolled user signs in with
two steps:

1. Password and captcha, as before.
2. A current 6-digit TOTP code or a one-time recovery code.

No session cookie is issued after the first step. Instead, the portal returns
a pending second-factor state (a ticket, or the enrollment data for a
required-but-unenrolled user), and the portal session is created only after
the second factor succeeds. The existing two-phase network authorization is
unchanged: after the portal session exists, the user must still select an
access rule and TTL and authorize the grant. TOTP never opens firewall
access by itself.

When `totp_required` is true but the user has no TOTP secret yet, the first
sign-in starts enrollment. The portal renders a scannable QR code in the
browser from the `otpauth://totp/...` URI returned by `/api/login`. The QR
generator is Nayuki's `qrcodegen.js` (MIT-licensed), vendored inline in
`index.html`; it runs offline and makes no CDN or other network request. The
manual base32 secret and the `otpauth://` URI remain available under the
collapsed fallback **Nem működik a QR? Írd be kézzel** (QR not working? Enter
it manually). After the user confirms the first code, the portal session is
created and 10 recovery codes are displayed exactly once. The QR is cleared
from the DOM on back-to-login and after successful enrollment.
Each recovery code can replace a 6-digit code once. Losing both the
authenticator and the recovery codes requires an admin reset (or the CLI
reset described below).

## Data model

User records live in `users.json` in the `hatarvedelem-state` volume
(`/var/lib/hatarvedelem/users.json`, mode `0600`). TOTP adds the following
fields:

| Field | Type | Meaning |
|---|---|---|
| `totp_required` | boolean | Admin-controlled policy. Defaults to `false` for new users. |
| `totp_secret` | string, base32 | The TOTP seed. Absent or empty when the user is not enrolled. Stored in plaintext at rest; it is not encrypted. |
| `totp_last_step` | integer | The last accepted TOTP time step, used to reject a replayed code. The step accepted during enrollment is recorded too, so the enrollment confirmation code cannot be replayed at a later login. Cleared by an admin/CLI reset. |
| `totp_recovery` | array of strings | Lowercase SHA-256 hashes of the unused recovery codes. The plaintext codes exist only in the one-time enrollment response. |
| `totp_enrolled` | boolean, derived | True when a TOTP secret is present. Derived from `totp_secret`; not a separate stored state. Exposed in the admin user representation; the secret and recovery hashes are not. |

An admin reset clears `totp_secret`, `totp_last_step` and `totp_recovery`.
The `totp_required` flag is intentionally retained, so the user is unenrolled
but still required to use 2FA and enrolls again at the next sign-in. The reset
also revokes the user's portal sessions and any pending second-factor tickets,
and writes an `admin_totp_reset` audit entry.

The admin user representation exposes `totp_required` and the derived
`totp_enrolled` flag only. It does not return `totp_secret` or
`totp_recovery`.

## API endpoints

All endpoints use the existing portal HTTP server and JSON request handling.
The password/captcha fields and origin checks of `/api/login` are the
existing login flow; TOTP adds the second-factor steps.

| Endpoint / action | Purpose |
|---|---|
| `POST /api/login` | First step: password and captcha. If the user needs TOTP, the response starts the second-factor flow and no session cookie is set. For a required-but-unenrolled user it returns the base32 secret, the `otpauth://` URI and a pending enrollment ticket; for an enrolled user it returns a pending verification ticket. For users who do not need TOTP, the existing one-step login behavior is unchanged. |
| `POST /api/login/totp` | Second step: pending ticket plus a current 6-digit code. On success, issues the normal portal session cookie. |
| `POST /api/login/totp/enroll` | Completes enrollment for a required-but-unenrolled user: takes the pending enrollment ticket and the first 6-digit code, verifies it, stores the secret and recovery hashes, returns 10 recovery codes exactly once and issues the portal session cookie. |
| `POST /api/login/recovery` | Second step using a one-time recovery code instead of a TOTP code. On success, issues the session cookie and removes that code's hash. |
| Admin `totp_reset` action | Admin user-management action. Clears the secret, step counter and recovery hashes, keeps `totp_required`, revokes the user's sessions and pending tickets, and audits `admin_totp_reset`. |

The session cookie is never sent before the second factor succeeds. Pending
tickets are not cookies and are not accepted as a portal session. The QR code
is rendered client-side from `otpauth_uri`; the server generates no image and
the ticket is never placed in a URL.

## Ticket semantics

- A ticket is created only after the password and captcha succeed for a user
  who needs a second factor.
- Tickets are held in memory only. They are not written to `users.json`,
  `fail2ban.json`, the audit log or any other state file, and they are lost on
  server restart.
- A ticket has a 300-second TTL. An expired ticket cannot be reused; the user
  restarts at the password/captcha step.
- A ticket is bound to the client IP address observed by the portal (the
  socket peer; `X-Forwarded-For` is not trusted). A ticket presented from a
  different IP is rejected.
- A ticket is single-use. A successful TOTP or recovery-code verification
  consumes it.
- A ticket allows at most 5 attempts. After the limit is reached the ticket is
  invalid and the user must start the sign-in flow again.
- A replay of an already accepted TOTP time step is rejected through
  `totp_last_step`. This includes the step accepted during enrollment, so the
  enrollment confirmation code cannot be reused at a later login. A recovery
  code hash is removed on first successful use.

## fail2ban integration

Wrong TOTP codes and wrong recovery codes count toward the same per-IP login
failure counter as wrong passwords. They use the existing fail2ban threshold,
window and ban duration. A banned IP is handled by the existing ban screen and
cannot sign in until the ban expires or is lifted. No ticket, secret or
recovery code is written to the ban state, drop log or audit log.

## Configuration

`HV_TOTP_ISSUER` sets the issuer and label used in the `otpauth://` URI
(default `Dropjak`). It is passed through `docker-compose.yml` as
`HV_TOTP_ISSUER: ${HV_TOTP_ISSUER:-Dropjak}` and documented in
`.env.example`. It changes only the label shown by the authenticator app; it
is not a security control. The 300-second ticket TTL and the 5-attempt limit
are fixed in this MVP.

## Admin reset and CLI

The admin UI action **2FA reset** is the preferred path while the portal is
running: it clears the enrollment, revokes the user's in-memory sessions and
records the audit event.

If the admin UI is unavailable, reset from the host:

```bash
docker compose exec hatarvedelem python3 /opt/hatarvedelem/server.py \
  user totp-reset <name>
```

Inside the container the same command is:

```bash
python3 /opt/hatarvedelem/server.py user totp-reset <name>
```

The CLI uses the existing `users.json` file lock, so it works while the server
is running. It prints only a clear status; it never prints the secret or
recovery codes. It does not revoke an already-open in-memory session, because
the running server owns session state. Use the admin UI when the server is up
and the session must be revoked immediately.

## Security and limitations

- **Plain HTTP.** The portal has no HTTPS listener. The base32 secret and
  `otpauth://` URI are transmitted and displayed in cleartext, the QR code
  encodes the same secret, and the 6-digit and recovery codes are sent in
  request bodies. Anyone able to sniff the LAN can capture and replay them.
  `HV_COOKIE_SECURE=1` protects only the cookie; it does not encrypt the page
  or API bodies. Restrict `HV_PORTAL_NET` to a trusted network. Integrated
  HTTPS termination is a follow-up, not part of the current implementation;
  the plan is in [`docs/caddy-proxy-terv.md`](caddy-proxy-terv.md).
- **Seeds at rest.** TOTP seeds are stored unencrypted in `users.json` (mode
  `0600`) inside the state volume. Protect the volume and any backups; a
  backup contains the seeds and the recovery-code hashes.
- **No secrets in logs or audit.** The portal does not log or audit TOTP
  secrets, pending tickets or recovery codes. Audit entries describe the
  action (for example `admin_totp_reset`), not the values.
- **Recovery codes.** Only lowercase SHA-256 hashes are stored. The plaintext
  is shown once at enrollment and cannot be recovered later. Losing both the
  authenticator and the recovery codes requires an admin or CLI reset.
- **QR code.** The QR is generated entirely in the browser from the
  `otpauth://` URI with the vendored Nayuki `qrcodegen.js` library (MIT).
  There is no CDN or runtime network request. The QR encodes the TOTP secret,
  so anyone who can see or screenshot the enrollment screen can add the
  account. The manual base32/URI fallback remains available.
- **CLI session limitation.** The CLI reset works with the server running, but
  it cannot revoke an already-open in-memory session. The admin UI action is
  required for immediate revocation.
- **Authorization is unchanged.** TOTP only establishes the portal session.
  Network access still requires the second phase (rule selection, TTL and
  authorization), and grants remain bound to the client IP and MAC address.
