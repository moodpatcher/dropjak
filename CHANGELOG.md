# Changelog

All notable changes to Dropjak are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The running version is stored in [`VERSION`](VERSION).

> Entries before 2.9.0 were reconstructed retroactively from git history and
> the documentation in this repository. Version tracking itself was introduced
> in 2.9.0.

## [3.11.0] - 2026-10-22

### Added

- **Proxy** admin tab (EN "Port proxy", DE "Port-Proxy"): kernel-level TCP/UDP
  port proxy with nftables DNAT, no userland process. The client IP is kept,
  and UDP works, so Minecraft (TCP 25565) and Simple Voice Chat (UDP 24454)
  can be forwarded.
  - **Forward** entries DNAT to a private IPv4 target (optional SNAT);
    **Input** entries redirect to another port on the host.
  - Access needs an active session whose rule (forward or host/input) lists
    the **listen port**. The forward chain uses its existing `ct original`
    check and Docker guard mark; input proxies are checked in the new
    `portproxy_input` chain, after the fail2ban, block, MAC and proxy-ban
    drops. Unauthorized input-proxy packets are dropped as
    `reason=portproxy`, which counts toward the drop-based fail2ban.
  - Only traffic addressed to the host (`fib daddr type local`) is
    translated, on the chosen interfaces (WAN, LAN or both).
  - The DNAT chain runs at prerouting priority -101, before Docker's DNAT
    (-100), so an entry wins over a Docker-published port on the same
    interfaces. Saving warns about such ports and about ports a local socket
    already listens on.
  - Stored as `port_proxies` in `firewall-settings.json` (at most 64
    entries). Saving uses the same apply, commit and rollback path as the
    other firewall settings, flushes conntrack for changed listen ports, and
    writes the `admin_portproxy_changed` audit event.
  - New chains `portproxy_prerouting`, `portproxy_nat`, `portproxy_input` and
    `portproxy_snat`; they are shown in the raw firewall view.

### Changed

- The forward chain's LAN MAC checks for port grants match the original
  direction only (`ct direction original`). Replies from a LAN DNAT target
  were dropped as a MAC mismatch.

## [3.10.0] - 2026-10-22

### Fixed

- Turning off **Automatikus tanúsítvány (Let's Encrypt)** (`proxy_acme`) now
  really stops Caddy from serving ACME certificates, on the entries and on
  the root (the HTTPS portal). Before, only new requests were refused
  (`/api/proxy/ask` 404): certmagic (Caddy 2.10.2) hands out a certificate it
  already holds in memory before asking `get_certificate` or `ask`, and a
  config reload does not evict on-demand certificates. Now the switch going
  from on to off makes the portal call `POST /stop` on Caddy's admin socket.
  `restart: unless-stopped` starts Caddy again with an empty cache.
  - Loading from `/data` still needs `ask`'s approval, so after the restart
    only uploaded certificates are served, and names without one fail the
    TLS handshake.
  - Nothing in `/data` is deleted: switching back on reloads the stored
    certificates without a new issuance.
- With ACME on, uploading a certificate restarts Caddy the same way, so the
  upload takes precedence over an ACME certificate already in memory.

### Added

- Caddy admin API on a Unix socket only: `admin
  unix//run/caddy-admin/admin.sock|0666`, no TCP port.
  - The socket lives in the new `caddy-admin` volume, mounted only into the
    portal and Caddy containers.
  - The portal entrypoint sets the directory to `root:hatarvedelem 0750`,
    so only Caddy (uid 0) and the portal's group can reach it. The portal
    still gets no Docker socket.
  - `HV_CADDY_ADMIN` sets the socket path; empty disables the feature.
  - Caddy gets `grace_period 5s`.
- A background thread (`hv-caddy`, only with `HV_PROXY=1`) handles the
  restart requests.
  - A request survives portal restarts (flag file `caddy-restart-pending` in
    the state volume).
  - It is retried with backoff (2–60 s) while Caddy is unreachable.
  - Each request restarts Caddy exactly once, never in a loop.
  - Otherwise the thread checks every 60 s that Caddy is reachable
    (`GET /config/admin`).
- The Domain settings section shows the Caddy status: reachable or not, the
  last restart, a pending restart and the last error (`caddy` in
  `/api/admin/state`).

## [3.9.1] - 2026-10-22

### Changed

- Proxy challenge page: the `sus.png` image is shifted 8px to the left so it
  lines up with the captcha box.

## [3.9.0] - 2026-10-22

### Added

- Challenge trigger `burst` (**Sok frissítés / spam**): when the same IP
  opens a page of the entry host 10 times within 30 seconds, a new
  challenge is required (a pass issued before the detection no longer
  counts). Only page opens are counted, in portal memory per IP and host.

## [3.8.1] - 2026-10-22

### Changed

- Port 80 (`http://` site in `deploy/Caddyfile`) no longer blindly redirects
  to `https://{host}{uri}`: forward_auth asks the new loopback-only
  `/api/proxy/redirect`, which always answers 3xx without audit. Root
  domains, enabled entries and unknown subdomains covered by an unexpired
  uploaded certificate get `308` to `https://<host><uri>`; other
  `<x>.<root>` names get `302` to `https://<root>/`, any other name or raw IP
  `302` to `https://<first root>/` (avoids the TLS error on names without a
  certificate). Without roots the old `308` stays. The Host
  (`X-Forwarded-Host`, else `Host`) is lowercased, port-stripped and strictly
  validated; invalid values count as foreign names (`400` without roots), and
  a bad `X-Forwarded-Uri` becomes `/`. `/.well-known/acme-challenge/*` (not
  an active challenge, which Caddy answers before routes) and an unreachable
  portal (`handle_errors`) keep the old redirect.

## [3.8.0] - 2026-10-21

### Added

- Per-entry **Challenge (ellenőrzés)** for the domain proxy: a collapsible
  part of each entry card on the Domainek tab with triggers `always`,
  `interval` (`interval_hours` 1–720), `daily`, `after_401`, `fail2ban`,
  `suspicious`, `new_ip` (stored as `challenge` in the entry; entries without
  it are unchanged). Evaluated only for requests `/api/proxy/auth` would let
  through: a page open gets a 403 page with `sus.png` and the login page's
  captcha (PoW or Turnstile), other requests a short 403 JSON
  (`code: proxy_challenge`). Challenge 403s are not counted by fail2ban and
  write no drop-log row; root domains are never challenged.
- Pass cookie `__Host-dropjak_pass` (Secure, HttpOnly, SameSite=Lax),
  HMAC-SHA256 signed with a per-process key; bound to the host, and to the
  client IP with `new_ip`. Caddy strips it from the `Cookie` header before
  the upstream.
- `GET`/`POST /api/gate/challenge` (Caddy: `/__dropjak/challenge` on the
  entry host): issues the PoW task and verifies the solution with the login
  code, then sets the pass. Loopback peer and challenge-enabled entry host
  only (else 404); failures count as a proxy fail2ban hit.
- `/__dropjak/sus.png` (portal: loopback-only `/api/proxy/sus.png`); `sus.png`
  is shipped by the Dockerfile and `install.sh`.
- `Fail2ban.last_hit(ip, proxy_only=False)`: read-only latest pending hit.
- Audit events `proxy_challenge_shown`, `proxy_challenge_passed`,
  `proxy_challenge_failed` (warning), labelled in the Naplók event filter.
- Unknown-subdomain challenge: a host `<x>.<root>` under a configured root
  that is not an enabled entry (unknown or disabled) and is covered by an
  unexpired uploaded certificate of that root (typically `*.<root>`) always
  gets the challenge page from `/api/proxy/auth` (403; short 403 JSON for
  non-navigation; bare 403 for banned IPs). `/api/proxy/cert` now serves by
  coverage, so such names get the uploaded certificate; `/api/proxy/ask`
  stays 404 for them (no ACME). A solved captcha sets no pass and returns
  `{"ok": true, "redirect": "https://<root>/"}`, which the page follows;
  failures count as a proxy fail2ban hit. Audit events carry
  `unknown_host: true`. Uncovered unknown names are unchanged (404).
- Naplók: **IP-cím / CIDR** filter (`ip=` on `/api/admin/logs`, single
  IPv4/IPv6 address or CIDR, invalid → 400), matching `ip`, `target`,
  `target_ip`, `session_ip` and `request_ip`. Proxy events show `host` +
  `path` (domain/certificate settings changes: domains or root) as the first,
  bold detail line; `visibility`, `triggers` and `unknown_host` are listed
  in the details.
- README and `deploy/HELYI-UTMUTATO.md`: DNS prerequisites for domains (A
  `<root>` and `*.<root>`, DNS only, no AAAA, wildcard certificate for the
  unknown-subdomain challenge).

### Changed

- `docker-compose.yml` mounts the host's `/etc/localtime` read-only into the
  portal container, so the `daily` challenge trigger uses the host's local
  midnight instead of UTC.

## [3.7.0] - 2026-10-21

### Added

- New fail2ban signal **Proxy: jogosulatlan kérések**: every 401 that
  `/api/proxy/auth` returns for a private entry counts against the real
  client IP (from Caddy's `X-Forwarded-For`). Config keys `proxy_enabled`,
  `proxy_max`, `proxy_window_seconds` (defaults: on, 20, 600 s; env
  `HV_FAIL2BAN_PROXY`, `HV_FAIL2BAN_PROXY_MAX`, `HV_FAIL2BAN_PROXY_WINDOW`);
  the ban duration is the shared `ban_seconds`. Legacy `fail2ban.json` files
  load with these defaults.
- `proxy_banned_v4` nft set and an input-chain drop (`reason=proxy-ban`) for
  TCP 80/443, placed before the proxy accepts and active regardless of
  `HV_PROXY`. A proxy ban closes only HTTP/HTTPS to the host; the portal port
  and other access stay open and sessions are kept.
- Proxy bans are stored separately (`proxy_bans` in `fail2ban.json`),
  restored on start, listed in the Fail2ban tab as `proxy` ("csak
  HTTP/HTTPS"), and can be lifted on their own (`unban` with
  `"proxy": true`); `unban_all` lifts both kinds. They coexist with a full
  ban on the same IP. A proxy-banned IP also gets 401 from
  `/api/proxy/auth`, and further 401s are not counted.
- Admin → Settings → **Domain beállítások**: toggle **Automatikus tanúsítvány
  (Let's Encrypt)** (`proxy_acme`, default on; legacy settings load as on).
  Off makes `/api/proxy/ask` always 404, so no ACME issuance happens.
- Uploaded certificates per root domain (`POST /api/admin/certs`, upload /
  replace / delete): chain + unencrypted key PEM, at most 64 KiB each,
  validated with stdlib `ssl` (key matches, not expired, SANs include the
  root or `*.<root>`). Stored as `certs/<root>.pem` + `.key` in the state
  volume (dir `0700`, files `0600`). The UI and `/api/admin/state`
  (`proxy_certs`) show only metadata (CN, SANs, issuer, validity with a
  14-day expiry warning, fingerprint, covered / not covered hostnames). Key
  and PEM never leave the server through the API or the audit log. Deleting
  a root domain deletes its certificate.
- Caddy `get_certificate http` → new loopback-only `GET /api/proxy/cert`
  (200 chain + key when an uploaded certificate covers `server_name`, else
  204 → on-demand ACME). Requests that came through Caddy (`X-Forwarded-*`
  headers or a root-domain Host) get 404.
- Audit event `proxy_page_opened` (ip, user, host, path without query,
  visibility) for page navigations that `/api/proxy/auth` lets through to an
  entry (`Sec-Fetch-Dest: document`, `Sec-Fetch-Mode: navigate`, or GET +
  `Accept: text/html` without those headers).
- Plain HTTP portal → HTTPS: with `HV_PROXY=1` (now also read by the
  portal), a GET/HEAD outside `/api/` that a WAN client sends directly to
  the portal port gets a `308` to `https://<first proxy root><path+query>`
  (audit `portal_https_redirect`, ahead of the foreign-Host captive
  redirect). Skipped for LAN (`HV_LAN_NET`) and loopback peers, requests via
  Caddy, fail2ban- and proxy-banned IPs, and when no certificate can serve
  the root (`proxy_acme` off and no unexpired uploaded certificate covers
  it). No HSTS.
- Drop log row `reason=proxy-unauthorized` (category **Proxy: jogosulatlan**)
  for every proxy 401, rate-limited to 30/min. It does not feed the
  drop-count / distinct-port fail2ban signals.

### Changed

- `proxy_banned_v4` is listed in the firewall snapshot and flushed on start
  with the other dynamic sets (the ban list is then restored).

## [3.6.0] - 2026-10-21

### Added

- Multiple proxy root domains: `proxy_domains` (up to 16 unique FQDNs;
  empty list = proxy off) replaces the single `proxy_domain`. Every entry
  has a `root` that must be one of them; an entry is identified by its full
  hostname `<name>.<root>`, so the same subdomain may exist under several
  roots. An entry whose hostname equals a root is rejected, and a root that
  still has entries cannot be deleted (400) until they are removed or moved.
- Admin → **Domainek**: a root-domain list (add/remove rows); each entry
  card has a root-domain picker next to the subdomain. The cards use two
  lines (subdomain, root, full hostname, visibility, active, delete / type,
  IP, port).
- Entry `visibility`: `private` (default; entries without it load as
  private) or `public`. A public enabled entry passes `/api/proxy/auth` for
  any client IP that is not fail2ban-banned, without a session or rule. UI:
  "Privát / Publikus" selector on the entry card; the domain-rule picker
  marks public entries "(publikus)".
- The portal is served over HTTPS on every root domain
  (`https://<root>/`): `/api/proxy/auth` returns `X-Dropjak-Upstream:
  127.0.0.1:<PORT>` for a root (and 404 when the original URI is under
  `/api/proxy/`). A loopback peer with a root `Host` passes the portal host
  check and gets a `Secure` session cookie.

### Changed

- Domain rules reference entries by full hostname
  (`domains: ["owui.z1.example.com"]`); a rule for `owui.<A>` does not open
  `owui.<B>`. Referential integrity (rule save, and proxy save rejecting
  removal, rename or re-rooting of a referenced entry) uses full hostnames.
- `/api/proxy/ask` allows every root and the full hostname of every enabled
  entry. The denial page's login link is `https://<root>/` (the entry's own
  root); `PORTAL_URL` is used only for the captive redirect.
- Client IP: `X-Forwarded-For` (last entry) is trusted only from a raw
  socket peer of exactly `127.0.0.1`/`::1`; otherwise ignored, and an invalid
  value falls back to the peer. Sessions, single-session-per-IP, rate limits,
  fail2ban and audit use this IP; the `/api/proxy/*` guard uses the raw peer.
- Audit `admin_settings_changed` (`action=proxy`) carries `proxy_domains`
  and `<name>.<root>:...` routes (` (public)` suffix for public entries).

### Migration

- On load, a legacy `proxy_domain` becomes a one-item `proxy_domains` and
  entries without `root` get it; the old key disappears on the next write.
  Legacy entries without any root were inert and are dropped (logged).
- Domain rules with bare entry names are rewritten to `<name>.<legacy root>`
  when the rules are loaded (backup `rules.json.domains-backup-*`). Without a
  legacy root a bare name is dropped from the rule and logged (a rule left
  with no entry is skipped); the rules file is neither quarantined nor
  rewritten by this.

## [3.5.0] - 2026-10-21

### Added

- Rule type **domain**: a rule listing proxy entries by name (`domains`),
  with label and TTLs but no ports, direction, ICMP or full access. It never
  touches nftables (empty grants: nothing granted, nothing revoked). It is
  assigned like any rule, can be a collection member (the resolved
  collection carries the union of `domains`), and can be selected in the
  portal alone or together with port rules. Shown as
  `Domain: <name>.<root>` in the rules list, pickers, portal and sessions.
- Proxy entries have a target type: `input` (default, also for entries
  without the field; host `127.0.0.1:<port>`, reserved ports as before) or
  `forward` (`ip` must be an RFC 1918 IPv4 address; any port 1–65535).

### Changed

- `/api/proxy/auth` allows a request only if the client IP's active,
  authorized session selected a domain rule listing the requested entry
  (`SessionManager.allows_domain`, replacing `has_authorized_session`).
  Full-access rules and admins get no bypass.
- The proxy configuration moved from Settings to its own admin tab
  **Domainek** (Domains), next to Rules.
- Referential integrity: a domain rule may only reference existing entries,
  and an entry referenced by a domain rule cannot be deleted or renamed
  (400). Rule writes and proxy saves are serialized by the admin lock.
- Rule create/update/duplicate audit events carry `domains`; access
  grant/modify events carry the selected `hosts`.

## [3.4.0] - 2026-10-21

### Added

- Portal-gated subdomain reverse proxy: an optional `caddy` service
  (`caddy:2.10.2-alpine`, compose profile `proxy`) serves
  `https://<name>.<root domain>` with on-demand automatic HTTPS and forwards
  to a port on the firewall host. The static `deploy/Caddyfile` has no admin
  API; Caddy asks the portal's loopback-only `/api/proxy/ask` (certificates
  only for configured names) and `/api/proxy/auth` (forward_auth: active,
  authorized, non-banned session for the client IP) on every request.
  Unauthorized clients get a "Nincs hozzáférés" page with a sign-in button;
  the root domain redirects to the portal.
- Admin → Settings → **Proxy**: root domain and subdomain → port routes
  (`proxy_domain`, `proxy_routes` in `firewall-settings.json`), validated
  as DNS names; the portal port, 22, 53, 67, 80, 443 and 2019 are reserved.
  Changes are audited as `admin_settings_changed` (`action=proxy`).
- `HV_PROXY=1` opens TCP 80/443 in the input chain after the fail2ban,
  block and MAC-binding drops (from the LAN only with a bound IP+MAC).
  The native installer always renders these rules commented out.

## [3.3.1] - 2026-10-21

### Fixed

- The ban duration is a shared setting again: it sits in a non-toggle
  **Közös beállítások** group together with the drop window, so turning
  off failed-sign-in monitoring no longer disables it. The three signal
  groups contain only their own thresholds.
- The admin form's numeric validation message uses the existing translated
  key, so English and German users no longer see the Hungarian singular
  mismatch.
- Clearing a numeric field while its group is enabled and then disabling
  the group no longer submits `0`: an empty disabled field falls back to
  the currently saved value, so both metrics and the login threshold stay
  valid.
- The `fail2ban_bans_released` audit event now carries `login_count` and
  `drop_count`, so releasing login and drop bans in one save keeps the
  source breakdown alongside `count` and `reason`.
- Stronger tests: the drop event-cap test now uses a port threshold above
  512, both single-zero legacy migrations are covered, the
  `HV_FAIL2BAN_DROP*` constructor defaults are checked, the release audit
  counts are asserted, the gateway threshold-preservation checks use
  non-default values, and the static UI test verifies the shared group,
  the validation key, and that `ban_minutes` is outside the login group.

## [3.3.0] - 2026-10-21

### Added

- Fail2ban's three monitored signals now have their own checkbox in
  Admin → Fail2ban: failed sign-ins, dropped packets, and distinct
  destination ports. Each one can be switched on or off independently.
- The settings form separates the three signals into bordered groups with
  short hints. A group's numeric fields are disabled while its checkbox is
  unchecked, but their values stay in the form draft and are saved.
- The two drop metrics share the drop window, shown once with a hint that
  both metrics use it.

### Changed

- Login monitoring and drop-based banning no longer depend on each other.
  Turning failed-sign-in monitoring off leaves both drop metrics counting
  and banning, and turning drop monitoring off does not touch login bans.
  Disabling the login switch releases only login-sourced automatic bans;
  disabling both drop metrics releases only drop-sourced bans. Manual bans
  are never released.
- `drop_enabled` is now a computed compatibility field in API/snapshot
  output (`drop_count_enabled or drop_ports_enabled`). The old input is
  still accepted: an explicit `drop_enabled: false` forces both drop
  metrics off, and `HV_FAIL2BAN_DROP=0` only gates the two metric defaults
  on first start.
- The drop event counters reset when either drop metric or threshold
  changes. Disabling login monitoring alone does not clear them.

### Removed

- The `0 = disabled` threshold mechanism. `drop_max` and `drop_ports` must
  be at least 1; `validate_config`/`configure` reject 0 with a range error,
  and `HV_FAIL2BAN_DROP_MAX=0` / `HV_FAIL2BAN_DROP_PORTS=0` fall back to
  the defaults instead of disabling a metric.
- The drop master checkbox in the admin settings form. Persisted legacy
  state with a zero threshold is migrated on load: the affected metric is
  switched off and its threshold reset to the default, without wiping the
  rest of the configuration.

## [3.2.1] - 2026-10-21

### Fixed

- The access-duration field shows the "óra" unit label again next to the
  number input; durations remain whole hours.
- The multi-selection duration hint no longer repeats the selected rule
  labels in the "felső korlát" list when every selected rule is binding.

## [3.2.0] - 2026-10-21

### Added

- Fail2ban drop banning can enable the two metrics independently. The admin
  tab has a checkbox for **dropped packets** and one for **distinct ports**;
  the API and CLI accept `drop_count_enabled` / `drop_ports_enabled`, and
  the new `HV_FAIL2BAN_DROP_COUNT_ENABLED` / `HV_FAIL2BAN_DROP_PORTS_ENABLED`
  variables provide first-start defaults. Switching a metric off stops it
  from counting, storing events and banning without touching existing bans.
- A threshold of `0` also disables the corresponding drop metric, so either
  measurement can be ignored without a separate switch. The counters are
  reset when a metric or threshold becomes active again, and the event
  history is capped using only the active thresholds.
- The **Logs** tab has an **Esemény** picker built from the known event
  codes and their localized labels, so event filtering no longer requires
  typing the raw code.

### Changed

- The audit `event` filter is case- and separator-insensitive
  (`access_granted`, `ACCESS-GRANTED` and `access granted` match the same
  rows), while a partial raw code such as `admin_` still matches that whole
  family. The free-text (`q`) filter now searches values only, not JSON key
  names, and also matches the normalized form of a value; `q=event` no
  longer matches every row.

### Fixed

- The authorized portal refreshes the rule catalog from `/api/status`
  instead of keeping the snapshot captured at sign-in. An administrator's
  edit is visible on the next poll, and **Módosítás** fetches a fresh status
  before opening the access screen, so the current rule definition and the
  server's remaining selections are shown.
- The 30-second status poll no longer throws the user out of the access
  (modify) screen. The screen stays in place, updates the rule cards, keeps
  still-valid selections and drops a selection that the server revoked
  because its rule changed, with a notice that the affected access must be
  authorized again.
- The session view reports when a rule edit revoked one of the selected
  accesses, instead of silently showing only the remaining grants.
- The access-duration hint lists every selected rule, marks the rule (or
  rules) that actually set the upper bound, keeps the full list in the
  tooltip, and uses plural wording when a selected rule requires at least
  one hour.

### Security

- The fail2ban event store holds only events that can contribute to an
  active metric, and an inactive metric cannot trigger a ban. Turning a
  metric off never extends or lifts an existing ban.
- Live rule propagation remains fail-closed: the affected selection is
  revoked at the commit point, and the changed definition is granted only
  by a new explicit authorization.

## [3.1.0] - 2026-10-21

### Added

- Simultaneous selection of multiple access rules in one session. The
  session grant is the per-direction (forward/input) union of the selected
  rules; `full` absorbs TCP/UDP/ICMP in the same direction and overlapping
  ports are granted once.
- Partial, targeted revocation when an administrator changes or deletes one
  of a session's selected rules. Only the affected selection and its exact
  departing kernel elements are removed; the remaining selections keep
  their grants and the session keeps its original expiry.
- A per-session TTL bounded by the strictest selected rule's `max_ttl`. A
  request above that limit is rejected instead of being silently truncated.
- HTTP/API support for multi-selection: `POST /api/access` accepts
  `{"rules": [ids...], "rule": first, "ttl": N}`; authorized responses and
  `/api/status` return `selected_rules`, `selected_rule_labels` and
  per-direction `grants`, while the legacy `rule`/`rule_label`/`grant`
  fields remain.
- The portal UI offers multi-select rule cards, union TTL bounds and a
  per-direction grant display; the admin session view shows every selected
  rule label.
- Audit events `access_granted` and `access_modified` record `rules`,
  `rule_labels` and `rule_count`, plus `removed_rules` on modification;
  `direction` can be `mixed`.
- A gated K6 live scenario (`tests/e2e_vm.py`, `HV_E2E_MULTI`,
  `HV_E2E_RULES`) for simultaneous multi-rule authorization. It is
  implemented and has not been run on the VM yet.

### Changed

- `Session` stores `rules: tuple[str, ...]` and
  `rule_parts: tuple[RuleSelection, ...]`; `rule`/`rule_label` remain the
  first-selection compatibility view. `snapshot()` exposes
  `selected_rules`, `selected_rule_labels` and per-direction `grants`.
- `revoke_rule` is now partial for multi-selection sessions; a session that
  selected only that rule is still removed entirely.
- An admin rule update revokes the rule and its dependent collections in
  one pass (`revoke_rules`), so a session is updated once instead of twice.

### Fixed

- Stale port/ICMP kernel elements are removed across ports-to-full
  transitions. `_subtract_grants` skips a departing `full` only when an
  active same-direction `full` covers it, and returns non-full departing
  parts covered by an active `full` for exact deletion so they cannot
  resurface later.
- Partial removal never re-grants an already expired session; expired
  sessions are fully removed instead.
- `conntrack_flush_removed` no longer performs an IP-wide flush while any
  grant remains, skips targeted deletion when a remaining grant is `full`,
  computes port/ICMP coverage across all remaining directions, and skips
  the cleanup instead of full-flushing when more than 16 targeted commands
  would be needed and grants remain.
- `validate()` now revokes expired and IP-changed sessions under the same
  `SessionManager._lock` as the session deletion.

### Security

- Multi-rule and partial-revoke paths are fail-closed: any firewall failure
  drops the session and revokes the old union (queued for retry where
  applicable), and HTTP returns 503.
- Every selected rule ID is resolved before authorization, so a failed
  lookup cannot leave a partial grant.
- Host SSH is still available only through an explicitly assigned input
  rule that lists TCP 22; full grants never open host SSH, and selection
  remains two-phase.

### Tests

- 517 unit tests pass. New coverage includes multi-selection union and
  overlap, exact grant subtraction, conntrack direction handling, expired
  partial revocation, one-pass `revoke_rules` revocation and lock scope.

### Documentation

- `docs/propagation-matrix.md` section 8 now describes the implemented
  multi-selection behavior, its tests and the residual runtime assumptions.

## [3.0.2] - 2026-10-20

### Fixed

- Firewall revocations are durable. A failed `nft` call now leaves a
  pending-revocation entry that is retried with backoff, and a partial
  revocation only removes elements that no remaining active session still
  needs. A full revocation ledger is logged and audited instead of silently
  dropping the cleanup.
- Startup never leaves orphaned grants behind. `HV_FLUSH_ON_START` and the
  new `HV_ALLOW_STALE_GRANTS_ON_START` use the same boolean parsing as the
  rest of the service; disabling the flush reconciles the dynamic sets to the
  empty in-memory session table unless the unsafe opt-in is explicitly set.
  `host_service_tcp`/`host_service_udp` are never flushed.
- Re-authorizing to a rule whose old grant cannot be revoked fails closed:
  the old session and its access are dropped, the user must authorize again,
  and no stale access survives.
- Admin block rules run before every grant on the forward and input paths
  and match the original pre-DNAT tuple, so a block also covers reply
  direction and WAN/Docker-sourced traffic. Block and pre-auth entries are
  strictly validated (port range, IPv4-only destination).
- Custom pre-auth and block chains are replaced in one `nft` transaction.
  Invalid or corrupted settings clear pre-auth (fail closed) while the
  last-known-good block chains stay installed; a failed settings commit
  restores the previous chains atomically.
- `host_service_tcp/udp` grow to 65536 entries and authorizing host access
  fails closed (HTTP 503) when the guard cannot be synchronized. A safe prune
  removes only ports no current rule references and with no live conntrack
  entry.
- A malformed or unreadable `client_mac` listing now blocks a LAN grant
  instead of silently granting without the MAC binding; non-LAN cleanup also
  removes stale MAC elements.
- Admin user updates revoke sessions before writing, restore the previous
  password hash if a later metadata or membership write fails, and audit
  `admin_user_update_failed`. Deleting a user through the CLI now removes
  group memberships too.
- Host-side CLI mutations go through the daemon control channel; an
  ambiguous or failed send is no longer followed by a local write. The
  control directory is `0700`, the pidfile is checked against a live daemon,
  and banned clients are rejected before and after login.
- `logout`, `terminate`, `revoke_user`, `revoke_rule` and the expiry reaper
  perform the firewall revoke under the same session lock that removed the
  session. A concurrent authorization can therefore no longer lose its
  fresh, overlapping grant to an older revocation.
- The user-store cache key includes the file inode, so replacing
  `users.json` cannot serve a stale cached record.

### Changed

- `HV_FIREWALL_WATCHDOG` can disable the entrypoint firewall watchdog, and
  `HV_ALLOW_STALE_GRANTS_ON_START` is passed through by `docker-compose.yml`;
  both are documented in `.env.example`.

### Tests

- New revocation, lock-scope, host-service-guard and atomic-chain tests; the
  block generator now rejects out-of-range ports and IPv6 destinations; admin
  update rollback, CLI group cleanup and post-login ban checks are covered.
- `tests/e2e_vm.py` gains gated live scenarios for the revocation matrix,
  natural expiry, block precedence, CLI propagation and restart behaviour.

### Documentation

- `docs/propagation-matrix.md` describes the final runtime behaviour of every
  administrative mutation path, including the residual runtime assumptions.

## [3.0.1] - 2026-10-20

### Fixed

- The Users table no longer labels an unassigned non-admin account as
  "default: all". It now distinguishes the forward-only legacy fallback
  from rules inherited through a group (Hungarian, English and German).
- The native `install.sh` installs every runtime module and asset
  (`settings_store.py`, `fail2ban.py`, `droplog.py`, `blocked.png`,
  `VERSION`, the nft template) and substitutes all seven nft placeholders,
  including `__FWD_MARK__` and `__DROP_LOG_GROUP__`. It also writes a
  systemd drop-in so the service uses the same mark and NFLOG group.
  Previously a bare-metal install could start with missing modules/assets
  or abort on a leftover placeholder.

### Documentation

- README documents the native systemd layout, the copied files and the
  placeholder defaults; `deploy/hv` is documented as a Docker-only helper
  that `install.sh` does not install. Remaining pre-3.0.0 `admin-full`
  wording was removed from the docs.

## [3.0.0] - 2026-10-20

### Removed

- The built-in `admin-full` rule. It is no longer returned by any API or
  effective-rule calculation, cannot be created, edited, duplicated,
  deleted, assigned or used as a collection member. The identifier itself
  stays permanently reserved so old data cannot resurrect hidden access.
- The dedicated `host_ssh_v4` nftables set, its MAC checks, its accept rule
  and every `host_ssh` plumbing method. Host SSH now uses only the ordinary
  `allowed_input_tcp` pair `(IP, 22)` granted by an assigned host rule.
- The `builtin_rule` field from `/api/admin/state` and the built-in rule
  notice from the admin UI.

### Changed

- Host SSH (TCP 22) is available only through an ordinary admin-created
  host (input) rule that explicitly lists TCP 22, assigned directly or via a
  group, with an active authorized portal session from the same source IP.
  Full forward rules and full/collection members never open host SSH.
- Loading `rules.json` drops the reserved legacy key with a `0600`
  `rules.json.admin-full-backup-<timestamp>` backup. A file containing only
  that key becomes an empty ruleset and is not reseeded. Persisted rule IDs
  are whitespace-normalized before the reserved-ID check, so variants such
  as `admin-full ` or ` admin-full` are treated as the legacy key; two raw
  keys that normalize to the same ID are a parse error and are not silently
  merged or rewritten.
- Legacy non-admin accounts without an explicit `rules` assignment no longer
  inherit input (host) rules through the all-rules fallback. They keep the
  forward rules only; host rules and collections containing an input member
  require an explicit user or group assignment.
- `users.json` and `groups.json` silently filter the reserved identifier,
  while preserving the `rules` key marker and all other assignments.
- Admins receive only explicitly assigned rules; an admin with no assignment
  has no effective rules.
- The established-SSH guard now checks only
  `(IP, 22) ∈ allowed_input_tcp`; the generic established accept cannot
  preserve a revoked SSH connection. The generic host guard keeps excluding
  TCP 22, and 8100 remains the only reserved host port.
- The container entrypoint removes a stale `host_ssh_v4` set after loading
  and flushing the new ruleset. If that cleanup fails, it logs a warning and
  continues starting the portal instead of aborting; the set is inert once
  the new input chain is loaded. The installer no longer touches that set.
- The installer, entrypoint and server startup warn loudly that the first
  ruleset load can cut SSH unless a TCP-22 host rule is already assigned;
  keep an out-of-band provider console available or bootstrap with
  `HV_SKIP_FIREWALL=1`.
- Documentation describes the single host-22 model, restart/re-authorization
  behaviour and the `Host TCP 22` firewall view. The SSH entry in
  `services.json` is outbound client access, not host SSH.

### Security

- A stale `admin-full` key or assignment in persisted JSON cannot grant
  access; the value is normalized and filtered before rule resolution and
  never appears in status, admin state or firewall output.
- The legacy rules fallback for unassigned non-admin accounts is forward-only
  and cannot grant host (input) access without an explicit assignment.

## [2.10.0] - 2026-10-20

### Added

- Configurable firewall/site name (`site_name` in `firewall-settings.json`,
  editable under **Admin → Settings → Firewall name**). It is shown in the
  portal header and browser title and is used as the TOTP issuer/label for
  new authenticator enrollments; empty falls back to `HV_TOTP_ISSUER` /
  `Dropjak`.
- Loud lockout warnings before the nftables rules are loaded and in the
  server log when no enabled admin account exists, because host SSH is
  closed without an active, authorized portal session.

### Changed

- The Settings page can rename this Dropjak instance without touching
  nftables. The change applies immediately to the UI and to new TOTP
  enrollments; existing authenticator entries keep their old issuer.
- Documentation clarifies that host SSH requires an admin-created host
  (input) rule that explicitly opens TCP 22; UDP 22 is an ordinary host-rule
  port and does not open SSH.

## [2.9.0] - 2026-10-20

### Added

- Version tracking: `VERSION`, `CHANGELOG.md`, the version shown in the
  portal footer, and the `version` field in `/api/status`.

### Changed

- Host (input) rules may now open TCP or UDP port 22. Only port 8100
  (portal) remains reserved by both validation and the kernel host accept.
- The established-SSH guard accepts a source while it is either in
  `host_ssh_v4` (built-in `admin-full`) or has the `(IP, 22)` pair in
  `allowed_input_tcp` (host rule).
- The generic host-revocation guard excludes TCP 22 so the two SSH routes can
  coexist; UDP 22 remains an ordinary host-rule port.
- Documentation updated for the new host-rule policy, the two SSH routes and
  versioning.

### Security

- Host rules are still admin-only, and custom full-access rules and full
  collection members never grant access.
- The built-in `admin-full` rule keeps using the dedicated `host_ssh_v4` set;
  a collection can grant 22 only through an input member that explicitly
  lists it.

## [2.8.0] - 2026-10-20

### Added

- Mixed-direction collections without their own direction: each member grants
  access in its own direction.

### Changed

- Firewall enforcement uses the directional grants of collection members
  rather than the display union.

## [2.7.0] - 2026-10-20

### Added

- Forward/input direction for rules; host rules use the `allowed_input_*`
  sets.
- Audit logging for authentication and administrative operations.

### Security

- Host rules are limited to explicit TCP/UDP ports: full access, ICMP and
  service lists are rejected. At this release both port 22 and port 8100 were
  rejected for host rules.

## [2.6.0] - 2026-10-20

### Changed

- Rule and access durations are expressed in whole hours; grants can last up
  to 30 days.

## [2.5.0] - 2026-10-20

### Added

- Collection rules, rule duplication and a random password generator.

### Changed

- Host SSH is gated to the built-in `admin-full` rule; the configurable host
  SSH policy was removed.

### Security

- Collections contain 1–64 single-level members and never grant full access.

## [2.4.0] - 2026-10-20

### Added

- Optional per-user TOTP two-factor authentication with QR enrollment.
- Self-service account requests with admin approval.

### Changed

- Settings cleanup: blocked destinations were removed from the UI.

## [2.3.0] - 2026-10-20

### Changed

- Design de-slop: type scale, flat surfaces, contrast and pills.
- The pre-de-slop snapshot was kept in `docs/`.

## [2.2.0] - 2026-10-20

### Added

- fail2ban login protection and ban management.
- Ban screen for blocked clients.
- Port-scanner and bot bans based on dropped traffic.
- Drop-log source/destination split, six reason groups and post-ban hit
  display.

### Fixed

- Manual ban visibility, admin session races and dark-theme rule-name
  contrast.

## [2.1.0] - 2026-10-20

### Added

- Spoofing and portal-bypass hardening.
- NFLOG drop logging.
- Custom firewall rules, raw and visual firewall views, and a drop-log chart.
- Pre-auth any-destination support and published WAN ports.
- Dark theme and SVG icons.

### Fixed

- NFLOG netlink byte order and flush batching.

## [2.0.1] - 2026-10-19

### Fixed

- The admin form keeps its values after validation errors.

### Changed

- Plain "Dropjak" tab title.
- README rewrite: English, Docker-only installation.

## [2.0.0] - 2026-10-19

### Added

- Initial release: nftables captive portal, Docker host networking,
  trilingual UI, users/groups/rules, two-phase login/authorization,
  fail-closed forwarding and an admin panel.
