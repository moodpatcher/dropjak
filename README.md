<p align="center">
  <img src="icon.png" alt="dropjak" width="180">
</p>

# dropjak

dropjak is a captive-portal firewall for Linux. It runs as a Docker
container in host network mode and controls the host's nftables forwarding
plane. All client traffic is **blocked by default**: a client gets network
access only after signing in through the portal and choosing one or more
access rules and a TTL in whole hours (up to 30 days). Only the ports and
services allowed by the selected rules are opened for the client's IP
address. Logout or expiry revokes access immediately.

The portal is available in Hungarian, English and German. It follows the
system light/dark preference and the theme can be switched manually in the
bottom-right corner.

## How it works

- The `forward` chain is fail-closed; the portal is the only publicly
  reachable service.
- A correct password alone does not grant network access. Sign-in is
  two-phase: authenticate, then explicitly select one or more access rules
  and a TTL.
- Account requests are optional and off by default. When an admin enables
  **Fiókkérelmek** in **Admin → Settings**, the login page shows **Fiók
  kérése** and a visitor can submit a username, password and email after the
  usual captcha. This creates a pending, disabled account with no rules or
  access; an admin approves or rejects it in **Admin → Users**. The email is
  stored as contact data only and is never sent or logged.
  See [docs/account-requests.md](docs/account-requests.md).
- Admins can duplicate any stored rule and combine existing individual
  rules into a **collection rule** whose TCP/UDP/ICMP permissions are the
  union of its members. The full-access identifier reserved by pre-3.0.0
  releases is not a rule and cannot be created, assigned, duplicated or
  used as a member. Collections can be assigned to users and groups like
  any other rule. See [docs/rule-collections.md](docs/rule-collections.md).
- Grants are implemented with nftables dynamic sets (`allowed_v4`,
  `allowed_tcp`, `allowed_udp`, `allowed_input_tcp`, `allowed_input_udp`,
  `allowed_icmp`, `client_mac`). Entries expire in the kernel
  even if the portal stops. The separate `host_service_tcp` /
  `host_service_udp` sets record every port ever declared by a host rule;
  they are add-only and are not flushed at startup, so they keep guarding
  established host connections across reloads.
- Each grant is bound to the client's IP **and MAC address**. The MAC is read
  from the host ARP table at authorization time; if it cannot be resolved,
  access is refused. Source-IP spoofing and DHCP lease takeover alone do not
  inherit an existing grant.
- Host SSH is gated by the portal session. An admin-created **input (host)**
  rule must explicitly list TCP 22; the portal then opens the `(IP, 22)`
  pair in `allowed_input_tcp` for an active, authorized session from the
  same source IP. UDP 22 is an ordinary host-rule port and does not open
  SSH. Custom full-access rules never open SSH, and a collection opens TCP
  22 only through an input member that explicitly lists it. Keep a provider
  console available: there is no separate host SSH switch. The `admin`
  service in `services.json` is outbound client SSH (forward direction), not
  host SSH. A restart flushes the dynamic sets, so clients must sign in and
  authorize again.
- Docker-published containers work too: forward rules match the pre-DNAT
  destination port, so the grant reaches the container. Forwarded packets
  are marked by the firewall; Docker's `DOCKER-USER` chain accepts only
  marked packets and drops everything else. If the firewall table disappears,
  Docker cannot open a bypass.
- Failed sign-ins are counted per source IP. When an IP reaches the
  configurable threshold within the time window, it is added to the
  `banned_v4` set and its packets are dropped. The same counter also watches
  unauthorized TCP traffic from clients that never sign in, so port scanners,
  bots probing open ports and similar sources are banned as well: a source is
  banned when it reaches the dropped-packet threshold, or when it tries enough
  distinct destination ports within the window. The portal (and DHCP) remain
  reachable so the client can see why it was banned and does not lose its IP
  address. Bans are persisted in `fail2ban.json` and survive a restart; manual
  bans can be created and lifted in the admin UI.
- Every restart flushes the dynamic sets; users must sign in again. The
  add-only `host_service_tcp` / `host_service_udp` guard sets are deliberately
  not flushed, so they can cut established host connections during startup.
  Persistent state (users, groups, rules, audit log, bans) lives in a Docker
  volume.
- The container uses `network_mode: host` because the host's `forward` chain
  cannot be managed from a Docker bridge namespace. Only one instance can run.

### Forward vs host rules

Every rule has a **direction**:

- **Forward** (default) sends traffic through the gateway: internet access or
  a Docker-published service. The rule matches the pre-DNAT destination port.
- **Input (host)** opens a service that runs **on the portal machine itself**,
  such as a game server listening on TCP/UDP 25566. Forward rules never make
  such a service reachable, because the traffic terminates on the host instead
  of passing through it.

Host rules are per-user and TTL-bound like any other rule. The portal adds the
authorized client IP to the `allowed_input_tcp` / `allowed_input_udp` sets, and
on the LAN the usual MAC binding also applies. Fail2ban bans and the anti-spoof
drops run before the host accept, so a banned client cannot reach the service
either.

Revocation, expiry and the conntrack flush close established connections. As a
second, in-kernel guard, every port ever declared by a host rule is recorded
in the add-only `host_service_tcp` / `host_service_udp` sets. The input chain
matches established client-to-host packets by their destination port against
these sets and drops the flow when the source IP is no longer in
`allowed_input_tcp` / `allowed_input_udp`. The existing LAN host-DNS/53 accepts
and DHCP renewals run before this guard, so forward DNS and address renewal
keep working. This closes the connection even if the conntrack flush fails or
the kernel recreates the flow (`nf_conntrack_tcp_loose`). Only port 8100
(portal) is excluded by both validation and the kernel host accept. TCP 22 is
deliberately left out of the generic host guard: established SSH is governed
solely by the SSH-specific guard, which accepts a source while it has the
`(IP, 22)` pair in `allowed_input_tcp` (an explicit host rule). UDP 22 is not
SSH and has no special guard.

Host rules accept explicit TCP/UDP ports only. Full access, ICMP and the legacy
service list are rejected. Only port 8100 (portal) is reserved; an
admin-created host rule may explicitly open TCP 22, which is the only way to
reach host SSH. UDP 22 is an ordinary host-rule port and is not SSH. Custom
full-access rules never open SSH, and collection members that are full access
are rejected; a collection can grant TCP 22 only through an input member that
explicitly lists it. Only administrators can create rules. The service must
listen on `0.0.0.0` (or the external interface), not only on `127.0.0.1`.
Collection rules have no direction of their own and may contain 1–64 members
with mixed directions; each member grants access in its own direction. See
[docs/host-rules.md](docs/host-rules.md) for the 25566 example and a quick
`nc` test.

## Requirements

- Linux host with nftables support and the `nft` binary.
- Docker Engine 20.10+ and Docker Compose v2 (`docker compose version`).
- Two network interfaces or VLANs: one facing clients (LAN), one facing the
  internet (WAN).
- Root access (or membership in the `docker` group) to start the container;
  root is required for `docker/setup-host.sh`.
- `net.ipv4.ip_forward=1` on the host. The setup script persists this.
- Optional: `dnsmasq` on the host for DHCP/DNS.

The image is built on Debian slim. The host distribution is independent; the
container programs the host kernel's nftables.

## Docker installation

### 1. Clone the repository

```bash
git clone https://github.com/moodpatcher/dropjak.git
cd dropjak
```

### 2. Prepare the host

Docker starts late in the boot process. To keep forwarded traffic blocked
until then, install the early boot guard:

```bash
sudo ./docker/setup-host.sh
```

The script installs `nftables` if needed, loads a boot-time `forward` chain
with `policy drop`, installs the `hatarvedelem-boot.service` unit, and
persists `net.ipv4.ip_forward=1` in
`/etc/sysctl.d/90-hatarvedelem.conf`. It does not touch SSH access.

### 3. Configure

```bash
cp .env.example .env
chmod 600 .env
editor .env
```

Required values:

| Variable | Example | Meaning |
|---|---|---|
| `HV_LAN_IF` | `eth1` | interface facing the clients |
| `HV_WAN_IF` | `eth0` | interface facing the internet |
| `HV_LAN_NET` | `192.168.10.0/24` | client network in CIDR form |
| `HV_PORTAL_NET` | `0.0.0.0/0` | source networks allowed to reach the portal |

If `HV_PORTAL_NET` is empty, it falls back to `HV_MGMT_NET`. The portal is
always reachable from the LAN interface. Use `0.0.0.0/0` only if the portal
must be reachable from the internet.

Find interface names with `ip -br link`. All other settings are documented in
`.env.example`.

### 4. Start

> **Lockout warning — read before the first start.**
>
> Loading the firewall cuts host SSH. Port 22/TCP remains reachable only
> from the same source IP that has an active, authorized portal session and
> an admin-created host (input) rule that explicitly lists TCP 22. The first
> ruleset load therefore cuts SSH unless such a rule is already assigned;
> have the provider console ready or start once with `HV_SKIP_FIREWALL=1`.
> Starting the container over SSH can terminate the current SSH session.
>
> Set up the admin account first: put the `HV_ADMIN_ENABLED=1`,
> `HV_ADMIN_USER` and `HV_ADMIN_PASSWORD` (or `HV_ADMIN_PASSWORD_FILE`)
> values from step 5 into `.env` before the first `docker compose up`.
> Without an existing admin account the portal login is impossible, so the
> Admin panel is unreachable and host SSH stays closed. Keep the
> provider/out-of-band console available so you can recover if the portal
> does not start.

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f hatarvedelem
```

Open the portal in a browser:

```
http://<lan-ip>:8100/
```

HTTP traffic from unauthenticated clients on port 80 is redirected to the
portal. The health check polls `/api/status`.

### 5. Create the first admin

Set these values in `.env`, then apply them:

```ini
HV_ADMIN_ENABLED=1
HV_ADMIN_USER=admin
HV_ADMIN_PASSWORD=<a-long-random-password>
```

```bash
docker compose up -d
```

The account is created (or its password updated) on container start. The
initial password must be changed at first sign-in. The **Admin** tab then
provides user, group, rule and audit-log management.

Always set these admin values **before** the first start: without an
existing admin account the portal login is impossible, and host SSH remains
closed. Keep the provider console available as the recovery path.

A user can also be added from the CLI:

```bash
printf '%s\n' '<password>' | docker compose run --rm -T hatarvedelem \
  python3 /opt/hatarvedelem/server.py user add alice --password-stdin
```

CLI-created users get the `user` role; promote them in **Admin → Users**.

### Two-factor authentication

TOTP 2FA is optional and configured per user. An admin can enable it with
the `totp_required` option when creating or editing a user in
**Admin → Users**; new users default to disabled. Enrolled users sign in
with two steps: password and captcha first, then a 6-digit code from an
authenticator app or a one-time recovery code. No session cookie is issued
until the second factor succeeds.

The first sign-in of a user who is required to use 2FA but is not enrolled
shows a scannable QR code generated in the browser, with the base32 secret
and `otpauth://totp/...` URI under a manual-entry fallback. After the first
code is confirmed, 10 recovery codes are shown exactly once. Each recovery code can
be used once in place of the 6-digit code. Store them offline: if both the
authenticator and the recovery codes are lost, an admin must reset 2FA.

Second-factor tickets are kept in memory for 300 seconds, are bound to the
client IP, are single-use and allow at most 5 attempts. Wrong TOTP and
recovery codes count toward fail2ban exactly like wrong passwords.

**2FA reset** in **Admin → Users** clears the secret, the TOTP state
(`totp_last_step`) and the recovery-code hashes, but keeps the account
required to use 2FA. It revokes the user's sessions and records an
`admin_totp_reset` audit entry. The user enrolls again at the next sign-in.

If the admin UI is unavailable, reset 2FA from the host:

```bash
docker compose exec hatarvedelem python3 /opt/hatarvedelem/server.py \
  user totp-reset alice
```

The command works while the server is running (it updates `users.json` under
the file lock) and prints only a status line, never secrets. It does not
revoke an already-open in-memory session, because the running server owns
session state; use the admin UI while the server is up.

The `otpauth://` issuer/label for new enrollments comes from the **Admin →
Settings → Firewall name** field. When it is empty, `HV_TOTP_ISSUER`
(default `Dropjak`) is used as the fallback (see `.env.example`). Changing
the name does not rename existing authenticator entries; re-enroll to pick
up the new issuer.

TOTP only creates the portal session. Network access still requires the
second phase: select one or more access rules and a TTL, then authorize the
grant. The second factor alone does not open the firewall.

## Operations

### Update

```bash
git pull
docker compose up -d --build
```

The entry point reloads the firewall rules idempotently. On portal start the
dynamic sets are flushed (`HV_FLUSH_ON_START=1`), so every user has to sign in
again. The add-only `host_service_*` guard sets are kept. State in the Docker
volume is preserved.

### Status and logs

```bash
docker compose ps
docker compose logs -f hatarvedelem
```

The **Firewall** admin tab has two views: a per-IP overview of the kernel
grants and portal sessions, and **Raw rules**, a read-only
`iptables -L -n`-style dump of the live nftables chains. The raw view includes
the `preauth`, `block`, `preauth_nat` and `block_nat` chains, so the effective
pre-auth and block rules can be inspected exactly as the kernel sees them. It
refreshes on demand and omits dynamic set contents (those are shown in the
overview).

The **Drop log** admin tab shows packets the firewall dropped, with source
and destination in separate columns and filters for source, destination,
protocol, port and free-text search. Entries are written to `drops.jsonl`
in the state volume and rotate at 10 MiB (5 files kept). The table labels
ordinary drops as **DROP** and rows produced by a fail2ban ban as
**fail2ban**; the raw kernel reason is kept in the JSON details. The log is
captured through NFLOG (`nfnetlink_log`) on group 5; the kernel must support
NFLOG, and the group must not be used by another process. Only packet
headers are stored, never payloads.

The **Fail2ban** admin tab protects the portal login and the network edge.
Failed passwords are counted per source IP; after the configured number of
attempts within the window, the IP is banned for the configured duration.
The tab shows the status, the active bans with a live countdown, and the
pending attempts. Any IP can also be banned or unbanned manually, and a ban
can be lifted before it expires. While a ban is active, the portal replaces
the sign-in screen for that IP with a ban notice and a live countdown; the
normal screen returns when the ban expires or is lifted. The threshold,
window and ban duration are editable at runtime; the `HV_FAIL2BAN*`
variables only provide the initial defaults. Bans are written to
`fail2ban.json` (mode `0600`) and restored on start. Every ban is recorded
in the drop log as a single `fail2ban` event with `event=ban`. Traffic from
the banned source is still sampled through NFLOG (rate-limited), but the
drop-log API folds those hits into the same event, so the UI shows one row
per ban with a short `fail2ban utáni kísérlet` (attempt after the ban) line,
the number of later attempts and the last one, instead of one row per
packet.

Drop-based banning covers clients that never attempt a sign-in. The portal
consumes the NFLOG drop events and counts unauthorized TCP traffic per source
IP. An IP is banned when, within the drop window, it reaches the dropped-
packet threshold or tries the configured number of distinct destination
ports. WAN-side traffic (`wan-drop`, `input-wan`) counts toward both tests;
LAN-side traffic (`no-grant`, `input-lan`) counts only toward the distinct-
port test, so a signed-out browser retrying a few connections is not banned.
DNS (TCP 53) and the portal port are ignored. The admin tab has three
independent switches: failed sign-ins (`enabled`), dropped packets
(`drop_count_enabled`) and distinct destination ports
(`drop_ports_enabled`). Each signal has its own threshold; the drop
thresholds and the shared drop window are `drop_max`, `drop_ports` and
`drop_window_seconds`. `HV_FAIL2BAN_DROP` only gates both drop metrics on
first start, and `HV_FAIL2BAN_DROP_COUNT_ENABLED` /
`HV_FAIL2BAN_DROP_PORTS_ENABLED` provide their first-start defaults.
Thresholds must be at least 1: there is no `0 = disabled` mode, and a
persisted legacy 0 is migrated on load to a disabled metric with the
default threshold. `drop_enabled` remains in the API as a computed
compatibility field (`drop_count_enabled or drop_ports_enabled`).

The three switches are independent. Turning failed-sign-in monitoring off
leaves both drop metrics counting and banning, and it releases only
login-sourced automatic bans. Turning both drop metrics off releases only
drop-sourced bans; manual bans are never released. Switching a metric off
does not otherwise lift bans that already exist; they expire normally. The
pending drop events are listed separately, and a drop-based ban is marked
`drop` in the ban list and on the ban screen.

If the admin UI is unreachable, the ban list can be managed from the CLI:

```bash
docker compose exec hatarvedelem python3 /opt/hatarvedelem/server.py fail2ban list
docker compose exec hatarvedelem python3 /opt/hatarvedelem/server.py fail2ban unban 203.0.113.10
docker compose exec hatarvedelem python3 /opt/hatarvedelem/server.py fail2ban unban-all
```

Run these as root (the default for `docker compose exec`); the ban/unban
commands call `nft` and need `NET_ADMIN`. The running portal reloads
`fail2ban.json` when it changes, so CLI changes appear in the admin UI within
a few seconds without a restart.

### Audit log

The **Logs** admin tab shows the JSON Lines security audit log
(`audit.jsonl` in the state volume): sign-ins, 2FA ticket lifecycle, access
and session changes, fail2ban and admin operations, plus CLI maintenance.
Every row has an `info`/`warn`/`alert` severity badge, and the **Szint**
selector filters by it, and the **Esemény** picker lists the known event codes
with their localized labels, so entries are searchable by event without
typing the raw code. The free-text search matches field values (not JSON key
names) and tolerates underscores, hyphens and spaces interchangeably. Opening
the tab, **Frissítés** and **Szűrők törlése** count as manual reads and are
themselves audited; the 5-second auto-refresh is not.

The log rotates by size (`HV_AUDIT_MAX_BYTES`, default 10 MiB;
`HV_AUDIT_KEEP`, default 5 files) and never contains passwords, TOTP codes or
secrets, recovery codes, cookies, full tokens or email addresses. Pending
2FA tickets appear only as a 12-character hash. Audit write failures are
reported in the process log and never block sign-in or admin actions. See
[docs/audit-log.md](docs/audit-log.md) for the event families, severity
rules, redaction guarantees and retention details.

### Firewall customization

The **Settings** admin tab manages three things:

- **Firewall name** — a display name for this Dropjak instance (at most 64
  characters; empty means `Dropjak`). It appears in the portal header and
  browser title, and it is the TOTP issuer/label for *new* authenticator
  enrollments. Existing authenticator entries keep their old issuer;
  re-enroll to pick up the new name. When no site name is set,
  `HV_TOTP_ISSUER` (default `Dropjak`) is used. Changing the name does not
  touch nftables.
- **Pre-auth rules** — destination (IP/CIDR, optional) and ports that are
  reachable from the LAN *before* portal sign-in. From the WAN side they
  apply only to DNATed (published Docker) services. An empty destination
  means any destination. For a published Docker port, use the pre-DNAT
  address (the VM IP), not the container's internal address. Every client
  can use them, so only deliberately public services belong here. Port 80
  entries also skip the captive-portal redirect. A fail2ban ban always
  overrides pre-auth: banned sources are dropped before the pre-auth chain,
  and an explicit ban drop is also the first rule inside that chain. Only
  the portal and DHCP remain reachable for a banned client.
- **Block rules** — destination/ports that are always dropped. The block chain
  is evaluated before every grant: it covers forwarded traffic in both
  directions on all interfaces (LAN, WAN/DNAT and the Docker container bridge)
  and traffic addressed to the host itself (host rules such as SSH and DNS).
  The only exemptions are loopback, the breakglass chain, DHCP and the portal,
  which are accepted earlier so a block entry cannot lock out management or
  the login page. Every packet is checked against the block chain, so adding
  or removing a block needs no conntrack flush: an active session or
  established flow cannot bypass a block, and removing a block immediately
  restores any still-valid grant without re-authorization (block changes do
  not revoke grants). A block overrides a pre-auth entry as well. Like
  pre-auth rules, the destination is matched against the pre-DNAT (original)
  tuple: for a published Docker service use the VM's public address and
  published host port, not the container's internal address — a block on the
  post-DNAT address does not match the forwarded path.

Changes are validated, applied to nftables, and only then written atomically
to `firewall-settings.json`; if the nftables update fails, the previous rules
are restored. Invalid or corrupted settings fall back to an empty pre-auth
list (fail-closed), while the last-known-good block chains stay installed.

### Subdomain proxy (Caddy)

An optional `caddy` service (Docker only) publishes local services on the
firewall host under subdomains with automatic HTTPS, e.g.
`https://owui.z1.example.com` → host port 3000, or a private-network host
behind the firewall (`forward`, e.g. `192.168.10.20:5001`). Each entry is
**private** (default) or **public**. A private entry lets through only clients
whose active, authorized session selected a **domain rule** listing that entry
(and that are not fail2ban-banned); full-access rules and the admin role grant
no domains. A public entry is open to every client IP that is not
fail2ban-banned, without a session. Everyone else sees a "Nincs hozzáférés"
page with a **Bejelentkezés** button that links to `https://<root>/` (the
entry's own root). Each root domain serves the portal itself over HTTPS
(e.g. `https://z1.example.com/`), with a `Secure` session cookie.
Several root domains can be configured (up to 16);
an entry belongs to one of them and is identified by its full hostname, so
`owui.z1.example.com` and `owui.z2.example.org` are separate entries.

1. DNS ("DNS only", no CDN proxy, so Caddy sees the real client IP), for
   every root: `A z1.example.com` and `A *.z1.example.com` → the host's
   public IPv4. No AAAA records: inbound IPv6 is dropped.
2. `.env`: `HV_PROXY=1` (opens TCP 80/443 in the input chain, after the
   fail2ban, block and MAC-binding drops; from the LAN only with a bound
   IP+MAC) and `COMPOSE_PROFILES=proxy` (starts `caddy`), then
   `docker compose up -d`.
3. Admin → **Domainek**: add the root domains and the entries: subdomain,
   root domain, type (`input` = host port, `forward` = private IPv4 + port)
   and port. Changes take effect immediately; nothing is reloaded. A root
   domain that still has entries cannot be deleted; delete or move them
   first.
4. Admin → Rules: create a rule of type **Domain (proxy)** listing the
   entries, and assign it to users/groups. It opens no firewall port; it can
   be combined with port rules in the portal or used in collections. The
   rule stores full hostnames; an entry referenced by a domain rule cannot be
   deleted, renamed or moved to another root.

[`deploy/Caddyfile`](deploy/Caddyfile) is static (`admin off`). Caddy asks the
portal's loopback-only endpoints on every request: `/api/proxy/ask` allows
on-demand certificates only for the configured names, and `/api/proxy/auth`
(forward_auth) checks the client IP's selected domain rules and returns the
upstream (`127.0.0.1:<port>` or `<ip>:<port>`). The portal, SSH, DNS, DHCP,
80/443 and 2019 cannot be `input` targets. Caddy reaches `forward` targets
from the host itself (output path, no forward chain). For a root domain
`/api/proxy/auth` returns the portal itself (`127.0.0.1:<PORT>`); the
`/api/proxy/*` paths are not reachable through Caddy.

Client IP behind Caddy: the portal trusts `X-Forwarded-For` only when the raw
socket peer is exactly `127.0.0.1` or `::1` (the host's Caddy, which replaces
any client-sent value with the real remote IP); then the last entry is the
client IP for sessions, rate limits, fail2ban and the audit log. From any other
peer the header is ignored. The `/api/proxy/*` loopback guard always uses the
raw peer. `HV_PORTAL_URL` stays the LAN/IP captive URL: LAN clients that are
not yet authorized keep using the plain-HTTP captive portal (LAN 443 is open
only for MAC-bound authorized clients), and fail2ban-banned WAN IPs are
dropped by nftables before reaching Caddy, so they see the ban screen only on
the plain-HTTP portal port.

### Backup

State is stored in the `hatarvedelem-state` volume
(`/var/lib/hatarvedelem`): `users.json`, `groups.json`, `rules.json`,
`audit.jsonl`, `drops.jsonl`, `fail2ban.json` and `firewall-settings.json`.

```bash
docker volume ls | grep hatarvedelem-state

docker run --rm -v dropjak_hatarvedelem-state:/data -v "$PWD":/backup \
  busybox tar czf /backup/dropjak-state.tar.gz -C /data .
```

The volume name depends on the Compose project name. `docker compose down -v`
deletes the volume; without `-v` it is kept.

## Native installation (systemd)

`install.sh` (run as root) installs the portal and the firewall as systemd
units. The runtime layout is `/opt/hatarvedelem`; the rendered ruleset is
written to `/etc/nftables/hatarvedelem.nft`. Besides the Python modules, the
installer copies `index.html`, `icon.png`, `blocked.png`, `services.json` and
`VERSION`, so the portal serves its assets and `/api/status` reports the
packaged version instead of `0.0.0`.

The ruleset template contains `__FWD_MARK__` and `__DROP_LOG_GROUP__` in
addition to the network placeholders. `install.sh` fills every placeholder
from the selected interfaces and networks, `HV_FWD_MARK` (default
`0x44524a4b`) and `HV_DROP_LOG_GROUP` (default `5`), matching
`docker/entrypoint.sh`. The same two values are passed to the portal unit
through a systemd drop-in so the portal and the drop-log listener agree with
the rendered ruleset.

The `deploy/hv` helper is a Docker Compose convenience wrapper and is **not**
installed by `install.sh`; it hard-codes the `/root/hatarvedelem` checkout
and Docker volume paths. Native installations use
`systemctl status hatarvedelem`, `journalctl -u hatarvedelem`, and
`/opt/hatarvedelem/server.py` for user and ban management. Installing `hv`
is optional and requires adapting those paths.

## Versioning

The running version is stored in [`VERSION`](VERSION), and release history is
recorded in [`CHANGELOG.md`](CHANGELOG.md). The portal footer shows the version,
and `GET /api/status` exposes the same value as `version`.

## Security notes

- Forwarding is fail-closed. If the portal or Docker fails to start, traffic
  stays blocked.
- Host SSH opens only for the source IP of an active, authorized portal
  session, through an admin-created host (input) rule that explicitly lists
  TCP 22 (`allowed_input_tcp`). UDP 22 is an ordinary host-rule port, not
  SSH. Custom full-access rules never open SSH, and a collection can grant
  TCP 22 only through an input member that explicitly lists it. Always keep
  an out-of-band console (provider console) available so you can recover if
  the portal does not start.
- The portal speaks plain HTTP. If it is reachable from an untrusted network,
  terminate TLS in front of it (reverse proxy) and set
  `HV_COOKIE_SECURE=1`; otherwise restrict `HV_PORTAL_NET` to a trusted
  management network. HTTP-only exposure allows credentials and session
  cookies to be sniffed.
- TOTP 2FA does not make the plain-HTTP portal confidential. The base32
  secret and `otpauth://` URI are displayed and transmitted in cleartext, and
  6-digit and recovery codes are sent in request bodies; anyone who can sniff
  the LAN can capture them. `HV_COOKIE_SECURE=1` protects only the cookie.
  Restrict `HV_PORTAL_NET` to a trusted network. Integrated HTTPS termination
  is still a follow-up, not part of the current implementation; the plan is in
  [docs/caddy-proxy-terv.md](docs/caddy-proxy-terv.md).
- TOTP secrets are stored unencrypted in `users.json` (mode `0600`) in the
  state volume. Protect the volume and its backups accordingly.
- MAC binding blocks source-IP spoofing and DHCP lease takeover, but MAC
  addresses are not authenticated. An attacker on the same layer-2 segment
  can clone an authorized client's IP and MAC, or ARP-spoof the gateway.
  Enable 802.1X, port security, DHCP snooping and dynamic ARP inspection on
  the switches where available.
- **Pre-auth rules intentionally bypass the portal.** Any client on the LAN
  can reach the configured destinations and ports without signing in. Treat
  them as publicly exposed services: keep the list minimal, and never add
  management services (SSH, database, hypervisor) unless they are separately
  protected. The block list overrides pre-auth rules.
- Fail2ban bans every packet from the source IP except traffic to the portal
  and DHCP, so a banned client loses all network access, including SSH, until
  the ban expires. The portal stays reachable from a banned IP, but only to
  show the ban screen: sign-in is refused while the ban is active, so you
  cannot lift your own ban from the portal. A manual ban can lock out your own
  management IP; lift it from the host console with the CLI commands above, or
  use the **breakglass** rule described below. Treat the thresholds and ban
  duration as a trade-off: a very low threshold makes it easy to lock out
  legitimate clients behind a shared NAT address. Drop banning deliberately
  ignores LAN packet counts and counts only distinct ports, but a port scanner
  behind the same NAT address can still get the whole address banned.
- The `breakglass` nftables chain is intentionally not flushed when the rules
  are reloaded, so an emergency SSH rule survives a restart. Keep it empty;
  remove the temporary rule as soon as the deployment is reachable.
- Keep `.env` at mode `0600`; it may contain the admin password. Alternatively
  use `HV_ADMIN_PASSWORD_FILE` with a read-only file or Docker secret. Never
  commit `.env`. `.secret` and state files are excluded by `.gitignore`.
- `docker compose down` leaves the `inet hatarvedelem` nftables table in place
  (fail-closed). Remove it explicitly if you want to tear the firewall down:
  `sudo nft delete table inet hatarvedelem`.
- If `firewalld` or `ufw` is active on the host, verify that it does not
  conflict with the firewall's forward rules. A dedicated firewall VM is
  recommended.
