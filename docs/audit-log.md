# Audit log

The portal keeps a security audit log of sign-ins, second-factor events,
access changes, session lifecycle, fail2ban actions, admin operations and
command-line maintenance. The audit log complements the process log and the
drop log: it records **who did what, from where, and with what result**, not
packet payloads.

## Location and format

The log is a JSON Lines file: one JSON object per line, UTF-8, no pretty
printing. It lives in the state volume:

```text
/var/lib/hatarvedelem/audit.jsonl
```

`HV_AUDIT_LOG` overrides the path. If it is empty, the file is
`audit.jsonl` under `HV_STATE_DIR` (or next to the program when
`HV_STATE_DIR` is unset). The file is created with mode `0600`; the directory
is created if needed, and each write is flushed with `fsync`.

Every entry has these common fields:

| Field | Meaning |
|---|---|
| `ts` | Unix timestamp (float). |
| `time` | UTC ISO-8601 timestamp for humans. |
| `event` | Event code (for example `login_success`). |
| `severity` | `info`, `warn` or `alert`. Legacy entries without the field count as `info`. |
| `ip`, `user`, `ua` | Optional actor fields set by HTTP handlers; `ua` is truncated to 300 characters. |

Event-specific fields follow. String values are truncated to 500 characters;
scalars are kept as-is. `GET /api/admin/logs` returns newest-first entries and
supports `limit`, `event`, `user`, `q`, `before`, `severity` and `ip`
filters. The **Logs** admin tab exposes those filters, including a **Szint**
(severity) selector and an **IP-cím / CIDR** field.

The `ip` filter takes a single IPv4/IPv6 address or a CIDR range
(`192.168.10.0/24`); anything else is a 400 with a Hungarian error. It
matches when any of `ip`, `target`, `target_ip`, `session_ip` or
`request_ip` holds an address inside the range, so admin actions on an
address (e.g. a ban or unban, which carry it in `target`) are found too.
Like the other filters it is applied while reading every rotated file,
before `limit`, and combines with `before` paging.

The `event` filter is case-insensitive and separator-insensitive:
`access_granted`, `ACCESS-GRANTED` and `access granted` all match. The admin
UI presents it as a picker built from the known event codes, so the label
shown on the row and the filter value cannot drift apart. A partial raw code
also works (`admin_` matches the whole admin family). The free-text `q`
filter searches **values only**, not JSON keys, so `q=event` does not match
every row; it matches both the raw stored value and a normalized form
(underscores and hyphens treated as spaces), so searching `access granted`
finds a row whose event field is `access_granted`.

## Severity levels

The central classification is `AUDIT_SEVERITY` in `gateway.py`; unknown or
legacy event codes default to `info`. A caller may pass an explicit
`severity=` where the outcome matters (for example an expired ticket that
already had wrong attempts becomes `warn`, and a failed code that reaches the
ban threshold becomes `alert`).

| Level | Meaning | Typical events |
|---|---|---|
| `info` | Normal lifecycle or a successful operation. | `login_success`, `portal_opened`, `totp_ticket_issued`, `session_replaced`, `service_start`, admin CRUD, CLI success. |
| `warn` | Rejected, denied or potentially suspicious operation. | `login_failed`, `access_denied`, `totp_failed`, `totp_ticket_rejected`, `session_ip_changed`, `admin_request_rejected`, CLI failures. |
| `alert` | Security-relevant failure or active protection. | `fail2ban_ban`, `totp_ticket_locked`, `firewall_error`, `fail2ban_error`, `settings_invalid`, `conntrack_failed`, `service_start_failed`, session reaper/shutdown errors. |

The `severity` filter is an exact, case-insensitive match on the stored
level; an empty value means all levels.

## Redaction guarantees

`AuditLog.write` applies the redaction rules centrally, so no call site can
accidentally persist a secret in a normal key:

- Exact keys `pass`, `password`, `password_hash`, `hash`, `secret`,
  `totp_secret`, `code`, `recovery`, `recovery_code`, `cookie`, `token`,
  `ticket` and `otpauth_uri` are **omitted** from the entry. The process log
  records only the field name (`[napló] érzékeny mező elhagyva: <key>`),
  never the value.
- Passwords, password hashes, TOTP codes and secrets, recovery codes and
  their hashes, cookies, `otpauth://` URIs and full session/ticket tokens are
  never written.
- Email addresses are never written to the audit log. Account requests audit
  the login name only.
- A pending login ticket is referenced only as `ticket_hash`: the first 12
  hexadecimal characters of `sha256(token)`. The raw ticket (which is enough
  to continue a sign-in) is never logged.
- Login entries may contain a short, non-usable prefix of the session token
  (`session`, 10 characters) to correlate a session with other entries. The
  cookie and the full token are not recorded.
- Recovery-code handling records only the count (`recovery_codes`), never a
  code or its hash.

The drop log and fail2ban state follow the same rule: ban records store the
source IP, user name, counters and reason strings, never credentials.

## TOTP ticket lifecycle

An abandoned or rejected second-factor prompt is explicitly visible in the
audit log. Ticket events carry the login name, purpose (`verify` or
`enroll`), IP, `ticket_hash` and lifecycle metadata.

| Event | Severity | When | Useful fields |
|---|---|---|---|
| `totp_ticket_issued` | `info` | After a correct password and captcha, when a TOTP/enrollment ticket is created. | `user`, `purpose`, `ticket_hash`, `ttl`; `secret_generated=true` for enrollment. |
| `totp_ticket_rejected` | `warn` | Missing ticket/code, unknown, expired, replayed, IP mismatch, wrong purpose, changed user state or locked ticket. | `user` (if known), `purpose`, `ticket_hash`, `reason`. |
| `totp_failed` | `warn`, or `alert` at the last attempt / when a ban starts | Every wrong TOTP or recovery code. | `user`, `method` (`totp`/`recovery`), `purpose`, `ticket_hash`, `attempts`, `remaining`, `banned`, `ban_until`. |
| `totp_ticket_locked` | `alert` | The attempt limit is reached; the ticket is destroyed. | `user`, `purpose`, `ticket_hash`, `attempts`, `reason="too_many_attempts"`. |
| `totp_ticket_expired` | `info` with 0 attempts, else `warn` | The 30-second sweeper, or another store operation, purges an expired ticket. This is the event for an abandoned 2FA prompt. | `user`, `ip`, `purpose`, `ticket_hash`, `attempts`, `age`, `ttl`, `reason="expired"`. |
| `totp_enroll_failed` | `alert` for persistence failure, else `warn` | Enrollment could not be saved or the user state changed. | `user`, `target`, `ticket_hash`, `reason`. |
| `totp_tickets_revoked` | `info` | Admin reject/reset/disable/delete revokes a user's pending tickets. | `target`, `count`, `reason`. |
| `totp_tickets_discarded` | `info` | Service shutdown discards all pending tickets. | `count`, `reason="service_stop"`. |

Rejection reasons are `bad_request`, `unknown`, `expired`, `ip_mismatch`,
`too_many_attempts`, `wrong_purpose`, `user_state_changed` and
`already_consumed`. The raw ticket is never stored, in memory only, and is
lost on restart.

## Other event families

- **Authentication and registration:** `login_success` (with
  `method="totp"`/`"recovery"` for second-factor logins), `login_failed`,
  `logout`, `logout_failed`, `password_changed`,
  `password_change_failed`, `registration_requested`,
  `registration_approved`, `registration_rejected`,
  `registration_failed`.
- **Access:** `access_granted`, `access_modified`, `access_denied`,
  `access_revoked`, `portal_opened`, `portal_host_redirect` (foreign Host
  header; the host is truncated), `portal_https_redirect` (a WAN client
  opened the plain HTTP portal directly and was sent to the HTTPS portal on
  the first proxy root domain; `target`), `proxy_page_opened` (a page navigation
  let through to a subdomain-proxy entry: `host`, `path` without query,
  at most 200 characters, `visibility`, `user` empty for public entries),
  `proxy_challenge_shown` (an entry's challenge page was served to a page
  navigation: `host`, `path`, `user`, `triggers` = comma-separated fired
  trigger ids), `proxy_challenge_passed` (captcha solved, pass cookie set:
  `host`, `triggers`) and `proxy_challenge_failed` (warning; captcha rejected
  and counted as a proxy fail2ban hit: `host`, `triggers`, `reason`). For an
  unknown or disabled subdomain covered by an uploaded certificate the three
  challenge events carry `unknown_host: true` instead of `triggers` (no
  `user`), and `passed` sets no pass cookie (the page goes to the root
  portal). The Logs tab shows `host` + `path` of proxy events as the first,
  bold detail line. Access entries carry `direction`
  (`forward`, `input`, or `mixed` when a collection rule grants in both
  directions); `ports`/`ports_label` show the union of the granted ports.
- **Sessions:** `session_replaced` (a new login from the same IP drops older
  sessions, including pending ones), `session_ip_changed` (cookie presented
  from another IP), `session_expired` (from `validate`, `authorize` or the
  reaper), `session_ended` (disabled/revoked user or a stale admin session),
  `session_reaper_error`, `session_shutdown_error`.
- **Admin:** denied and rejected requests (`admin_denied`,
  `admin_request_rejected`, `admin_action_failed`), user/group/rule CRUD,
  settings and fail2ban changes (proxy certificate upload/delete as
  `admin_settings_changed` with `action=proxy_cert_upload|proxy_cert_delete`
  and only `target` root, `sans`, `not_after`, `fingerprint`), port proxy
  changes (`admin_portproxy_changed` with `port_proxies` summary,
  `port_proxy_count` and the conntrack-flushed `flushed_ports`), session termination, TOTP reset, admin
  provisioning, and `admin_logs_read`.
- **fail2ban:** `fail2ban_ban` (automatic login/drop bans and manual bans,
  with `source`, `manual`, `attempts`, `user`, `until`,
  `sessions_revoked`), `fail2ban_unban`, `fail2ban_bans_released`,
  `fail2ban_ban_evicted`, `fail2ban_load_error`, `fail2ban_sync_failed` and
  `fail2ban_error`.
- **Service and firewall:** `service_start` (configuration counts, TTL,
  fail2ban state, dry-run flag), `service_stop` (real revoked-session count),
  `service_start_failed`, `firewall_error` (flush, health, apply, rollback,
  revoke), `settings_invalid` and `conntrack_failed` (`operation=flush_port`
  for a port proxy flush, with `ip` set to `<proto>/<port>`).
- **CLI:** `cli_user_created`, `cli_password_changed`, `cli_user_deleted`,
  `cli_totp_reset`, `cli_fail2ban_ban`, `cli_fail2ban_unban` and
  `cli_action_failed`, with `actor="cli"` where applicable. The CLI uses the
  same `HV_AUDIT_LOG` / `HV_STATE_DIR` rules as the server.

Aggregate admin, password-change and fail2ban operations revoke many
sessions or grants at once. These are recorded as one aggregate entry with a
count; the portal deliberately does not write a separate audit row for every
revoked session. Per-IP session events exist for the cases that matter for
incident response: replacement, IP change, expiry and forced ending.

## Audit of audit reads and failure handling

The Logs admin tab loads entries automatically every 5 seconds. Only
user-initiated reads (opening the tab, **Frissítés**, **Szűrők törlése**) send
`manual=1`; the automatic refresh does not. A manual read appends
`admin_logs_read` with the admin user, `limit`, the event/user/severity/ip
filters, `q_present`, `before_present` and the number of returned rows. Query
text itself is not copied into the audit entry.

Audit writes are best-effort by design. `AuditLog.write` catches filesystem
errors and reports them to the process log; callers such as the ticket store,
session manager, fail2ban and CLI wrap writes as well. A full disk or a
permission problem therefore never blocks sign-in, logout, authorization, a
ban or an admin action. The trade-off is that a failed write is visible only
in the process log, so keep `docker compose logs` monitoring in place.

## Rotation, retention and backup

Rotation is size-based and happens before a write when the current file
reaches the limit:

| Variable | Default | Notes |
|---|---|---|
| `HV_AUDIT_LOG` | `<state>/audit.jsonl` | Absolute path inside the container is `/var/lib/hatarvedelem/audit.jsonl`. |
| `HV_AUDIT_MAX_BYTES` | `10485760` (10 MiB) | Minimum 256 KiB. |
| `HV_AUDIT_KEEP` | `5` | Clamped to 1–20 rotated files. |

The current file becomes `audit.jsonl.1`; older files shift to `.2` … `.keep`.
`/api/admin/logs` reads the current file and all rotated files, then sorts
newest-first and applies the limit. Rotation failures are reported to the
process log and do not stop authentication.

The audit log is stored on the local state volume, not shipped to a remote
SIEM. Anyone with root on the host or access to the volume can read or
modify it. Protect the volume, restrict root access, and include
`audit.jsonl*` in backups together with the other state files. For stronger
tamper evidence, ship a copy off-host.
