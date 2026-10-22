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

- The `forward` chain is fail-closed. By default the portal is the only
  publicly reachable service; with `HV_PROXY=1`, Caddy also listens on TCP
  80/443 for the configured root domains (see
  [Subdomain proxy](#subdomain-proxy-caddy)).
- A correct password alone does not grant network access. Sign-in is
  two-phase: authenticate, then explicitly select one or more access rules
  and a TTL.
- Several assigned rules can be selected at once, up to 16
  (`limits.max_rules` in `GET /api/status`). **Select all** on the "Choose
  an access rule" screen selects every assigned rule up to that limit, and
  **Max** sets the duration to the largest whole number of hours the current
  selection allows (the minimum of the global `max_ttl` and the selected
  rules' `max_ttl`).
- Account requests are optional and off by default. When an admin enables
  **Fiókkérelmek** in **Admin → Settings**, the login page shows **Fiók
  kérése** and a visitor can submit a username, password and email after the
  usual captcha. This creates a pending, disabled account with no rules or
  access; an admin approves or rejects it in **Admin → Users**. The email is
  stored as contact data only and is never sent or logged.
  See [Account requests](DOKUMENTACIO.md#fiokigenyles).
- Admins can duplicate any stored rule and combine existing individual rules
  into a **collection rule** whose grants are the union of its members':
  forward TCP/UDP/ICMP ports, input (host) ports, and proxy hostnames from
  domain rules or domain-mode service rules. Service rules can be members
  too. The full-access identifier reserved by pre-3.0.0 releases is not a
  rule and cannot be created, assigned, duplicated or used as a member.
  Collections can be assigned to users and groups like any other rule. See
  [Collection rules and rule duplication](DOKUMENTACIO.md#gyujtoszabalyok).
- A **service rule** grants access through one or more tunnel services
  instead of listing ports. Referenced port-mode services contribute their
  WAN listen ports as forward access. Referenced domain-mode services
  contribute only their hostname through the portal/Caddy proxy and open no
  nftables or WAN port. A mixed service rule still opens the port services
  and admits the domains. Disabling the agent or service fails closed: the
  referencing rule's resolved grants are recalculated and its sessions are
  revoked.
- **Tunnel agents** reach a private Docker network behind NAT through a
  WireGuard tunnel, without opening a port at home. The portal creates the
  `dropjak0` interface in the host namespace (server `10.77.0.1`, agents
  `10.77.0.2`–`10.77.0.254`) and opens UDP 51820 (default) on the WAN only
  while an enabled agent exists. Port-mode services are DNATed like port
  proxies, so a client still needs an authorized session and a matching rule
  unless the service is marked public. A **domain-mode service** is served
  by Caddy under a configured root domain: the portal assigns its internal
  tunnel port automatically (41000–60999), and no WAN port or DNAT is
  created. It is selectable both in a **Domain (proxy)** rule and in a
  **Service** rule. See [Tunnels](DOKUMENTACIO.md#alagut) and the
  [Tunnel agents](#tunnel-agents-wireguard) section below.
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
  console available: there is no separate host SSH switch. The legacy `ssh`
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
[Host (input) rules](DOKUMENTACIO.md#host-szabalyok) for the 25566 example and
a quick `nc` test.

**Service rules** and **domain rules** are separate rule types, not
directions. A service rule resolves its grants from the tunnel services it
references: forward listen ports for port-mode services and/or proxy
hostnames for domain-mode services. A domain rule admits proxy hostnames
only. Neither can be an input (host) rule, and neither opens a host port.

## Requirements

- Linux host with nftables support and the `nft` binary.
- Docker Engine 20.10+ and Docker Compose v2 (`docker compose version`).
- Two network interfaces or VLANs: one facing clients (LAN), one facing the
  internet (WAN).
- Root access (or membership in the `docker` group) to start the container;
  root is required for `docker/setup-host.sh`.
- `net.ipv4.ip_forward=1` on the host. The setup script persists this.
- Optional: `dnsmasq` on the host for DHCP/DNS.
- Optional: WireGuard support in the host kernel (module or built in, Linux
  5.6+) for tunnel agents.

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

Every 401 ("Nincs hozzáférés" page) from the subdomain proxy also adds a
**Proxy: jogosulatlan** row (`reason=proxy-unauthorized`, `source=proxy`):
the client IP as source, the requested hostname as destination, `tcp 443`,
and the path without query string (at most 200 characters). The portal
writes these rows directly, rate-limited like the nft log rules (30 per
minute, global). They do not feed the drop-count or distinct-port fail2ban
signals; repeated 401s are counted only by the separate proxy signal.

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

A fourth, independent signal covers the subdomain proxy (`proxy_enabled`,
`proxy_max`, `proxy_window_seconds`; defaults on, 20 hits in 600 s; first-
start defaults from `HV_FAIL2BAN_PROXY`, `HV_FAIL2BAN_PROXY_MAX`,
`HV_FAIL2BAN_PROXY_WINDOW`). Every 401 that `/api/proxy/auth` returns for a
private entry counts against the real client IP (the `X-Forwarded-For` value
from Caddy); 200, the root-domain portal, 404 for unknown hosts and public
entries do not count, and a successful request does not reset the counter.
This ban is narrower: the IP goes into a separate `proxy_banned_v4` set that
drops only TCP 80 and 443 to the host (everything Caddy serves, including
the HTTPS portal), logged as `reason=proxy-ban`. The plain portal port and
all other access stay open, so the user can still sign in at
`http://<host>:<PORT>`. Sessions are not revoked. The ban uses the shared ban
duration, is stored under `proxy_bans` in `fail2ban.json`, restored on start,
and listed in the ban list as `proxy` ("csak HTTP/HTTPS"). It is separate
from a full ban on the same IP: unbanning one leaves the other. A full or
proxy ban stops further counting, and a proxy-banned IP also gets 401 from
`/api/proxy/auth`. Turning the signal off releases only proxy bans.

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

Page opens through the subdomain proxy are logged as `proxy_page_opened`
(ip, user, host, path, visibility) when `/api/proxy/auth` lets a request
through to an entry (not the root-domain portal) and the request is a page
navigation: `Sec-Fetch-Dest: document`, or `Sec-Fetch-Mode: navigate` when
there is no `Sec-Fetch-Dest`, or, without either header, a GET whose `Accept`
contains `text/html`. Assets, XHR/fetch and iframes are not logged. `user` is
the session user for private entries and empty for public ones; `path` has
no query string (it may carry tokens) and is cut to 200 characters.

The **IP-cím / CIDR** filter (`ip=` on `GET /api/admin/logs`) takes one IPv4
or IPv6 address or a CIDR range (e.g. `192.168.10.0/24`; invalid input is a
400) and matches the `ip`, `target`, `target_ip`, `session_ip` and
`request_ip` fields, so an admin ban/unban of that address (`target`) shows up
as well. It combines with the other filters and the `before` paging like they
do. Proxy events (`proxy_page_opened`, `proxy_challenge_*`) show `host` and
`path` as the first, bold line of the details; domain and certificate
settings changes show the domains/entries or the root there.

The log rotates by size (`HV_AUDIT_MAX_BYTES`, default 10 MiB;
`HV_AUDIT_KEEP`, default 5 files) and never contains passwords, TOTP codes or
secrets, recovery codes, cookies, full tokens or email addresses. Pending
2FA tickets appear only as a 12-character hash. Audit write failures are
reported in the process log and never block sign-in or admin actions. See
[the audit log section](DOKUMENTACIO.md#audit-naplo) for the event families,
severity rules, redaction guarantees and retention details.

### Firewall customization

The **Settings** admin tab manages these things (plus account requests and
the domain settings, see [Subdomain proxy](#subdomain-proxy-caddy)):

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
With `HV_PROXY=1`, a WAN client that opens the plain HTTP portal directly
(`http://<ip>:8100/...`) gets a `308` to `https://<first root><same path and
query>` (audit `portal_https_redirect`), only for GET/HEAD outside `/api/`
and only when a certificate can serve the root (`proxy_acme` on, or an
unexpired uploaded certificate covers it). LAN clients, loopback peers,
requests already through Caddy, and fail2ban- or proxy-banned IPs (which
cannot reach 443) keep the plain HTTP portal. No HSTS is sent.
Several root domains can be configured (up to 16);
an entry belongs to one of them and is identified by its full hostname, so
`owui.z1.example.com` and `owui.z2.example.org` are separate entries.

**Előfeltétel domain használatához (prerequisite):** for every root domain
two DNS A records, both to the server's public IPv4:

| Record | Value |
|---|---|
| `A <root>` (e.g. `z1.example.com`) | server public IP |
| `A *.<root>` (e.g. `*.z1.example.com`) | same IP |

- At Cloudflare both **DNS only** (grey cloud), no CDN proxy, so Caddy sees
  the real client IP.
- No AAAA records: inbound IPv6 is dropped.
- The [unknown-subdomain challenge](#unknown-subdomains) needs an uploaded
  certificate covering `*.<root>`; ACME is never used for unknown names.

1. DNS: the two A records above, for every root.
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
   entries (and any domain-mode tunnel services), and assign it to
   users/groups. It opens no firewall port; it can be combined with port
   rules in the portal or used in collections. The rule stores full
   hostnames; an entry or tunnel service referenced by a domain rule cannot
   be deleted, renamed or moved to another root.

[`deploy/Caddyfile`](deploy/Caddyfile) is static (never reloaded). Its admin API
listens only on a Unix socket (`/run/caddy-admin/admin.sock`, no TCP port) in
the `caddy-admin` volume, which only the portal and Caddy containers mount
(directory `root:hatarvedelem 0750`, set by the portal entrypoint; Caddy runs
as root without `DAC_OVERRIDE`, so only uid 0 and the portal's group reach
it). The portal uses it for one call, `POST /stop` (see Domain settings
below); `HV_CADDY_ADMIN` sets the socket path, empty disables it. Caddy asks the
portal's loopback-only endpoints on every request: `/api/proxy/ask` allows
on-demand certificates only for the configured names, and `/api/proxy/auth`
(forward_auth) checks the client IP's selected domain rules and returns the
upstream (`127.0.0.1:<port>` or `<ip>:<port>`). The portal, SSH, DNS, DHCP,
80/443 and 2019 cannot be `input` targets. Caddy reaches `forward` targets
from the host itself (output path, no forward chain). For a root domain
`/api/proxy/auth` returns the portal itself (`127.0.0.1:<PORT>`); the
`/api/proxy/*` paths are not reachable through Caddy.

Plain HTTP (port 80) asks the portal for the redirect target (forward_auth to
the loopback-only `/api/proxy/redirect`, which always answers 3xx, no audit):
a root domain, an enabled entry, or an unknown `<x>.<root>` covered by an
unexpired uploaded certificate gets `308` to `https://<host><uri>`; any other
`<x>.<root>` gets `302` to `https://<root>/`, and any other name or raw IP
`302` to `https://<first root>/` (no certificate exists for those names).
Without roots it stays `308` to `https://<host><uri>`. The Host is lowercased,
the port stripped, and anything that is not a valid hostname or IP is treated
as a foreign name (`400` without roots), so the `Location` only ever names the
request's own (configured) host or a root. Active ACME HTTP-01 challenges are
answered by Caddy before any route; other `/.well-known/acme-challenge/` paths
and an unreachable portal keep the old `308` to `https://<host><uri>`.

Client IP behind Caddy: the portal trusts `X-Forwarded-For` only when the raw
socket peer is exactly `127.0.0.1` or `::1` (the host's Caddy, which replaces
any client-sent value with the real remote IP); then the last entry is the
client IP for sessions, rate limits, fail2ban and the audit log. From any other
peer the header is ignored. The `/api/proxy/*` loopback guard always uses the
raw peer. `HV_PORTAL_URL` stays the LAN/IP captive URL: LAN clients that are
not yet authorized keep using the plain-HTTP captive portal (LAN 443 is open
only for MAC-bound authorized clients), and fail2ban-banned WAN IPs are
dropped by nftables before reaching Caddy, so they see the ban screen only on
the plain-HTTP portal port. Repeated 401s on private entries lead to a
fail2ban proxy ban that closes only 80/443 (see the Fail2ban section above).

#### Domain settings and certificates

Admin → Settings → **Domain beállítások** controls the HTTPS certificates:

- **Automatikus tanúsítvány (Let's Encrypt)** (`proxy_acme`, default on;
  settings files without the key load as on). When off, `/api/proxy/ask`
  always answers 404, so Caddy requests no ACME certificate at all; only
  names covered by an uploaded certificate work over HTTPS. Caddy (certmagic)
  serves a certificate already in its memory before it asks `get_certificate`
  or `ask`, and a config reload does not evict on-demand certificates, so
  turning the switch off also restarts Caddy: the portal calls `POST /stop`
  on the admin socket and `restart: unless-stopped` starts it again with an
  empty cache (sub-second locally, a few seconds of proxy downtime at most;
  `grace_period 5s`). Loading from the `/data` volume needs `ask`'s approval,
  so after the restart no stored ACME certificate is served either. Nothing
  in `/data` is deleted: turning the switch back on loads the stored
  certificates again without a new issuance. Uploading a certificate while
  the switch is on restarts Caddy the same way, so the upload wins over an
  ACME certificate already in memory. The request survives portal restarts
  (flag file `caddy-restart-pending` in the state volume) and is retried with
  backoff (2 s … 60 s) while Caddy is unreachable; each request restarts
  Caddy exactly once. The section shows the Caddy status: reachable or not
  (checked every 60 s), last restart, pending restart, last error.
- Per root domain, a certificate chain PEM (leaf first) and an unencrypted
  private key PEM can be uploaded, replaced or deleted (`POST
  /api/admin/certs`, `{"action": "upload"|"delete", "root", "cert", "key"}`,
  admin only). The upload is checked before it is stored: at most 64 KiB per
  PEM, the key must match the certificate, the certificate must not be
  expired, and its SANs must include the root or `*.<root>`. The tab shows
  only metadata: subject CN, SANs, issuer, validity (with a warning when it
  expires within 14 days or has expired), the SHA-256 fingerprint, and which
  configured hostnames (the root and its entries) it covers and which it does
  not (a wildcard covers exactly one label). The key and the PEM are never
  returned by any API and never written to the audit log; the audit records
  only root, SANs, `notAfter` and fingerprint.
- Files: `certs/<root>.pem` and `certs/<root>.key` in the state volume
  (directory `0700`, files `0600`, written atomically). Deleting a root
  domain on the Domainek tab also deletes its certificate.

Caddy fetches certificates from the portal with `get_certificate http
http://127.0.0.1:<PORT>/api/proxy/cert` (in the `tls` block, next to
`on_demand`). On a TLS handshake for a name it has no certificate in memory
for, Caddy calls the endpoint with `server_name`; the portal answers 200
with the chain followed by the key when an uploaded, unexpired certificate of
that name's root covers it (also for a name that is not an entry, see
[Unknown subdomains](#unknown-subdomains)), otherwise 204, and Caddy falls back to on-demand
ACME (which still goes through `/api/proxy/ask`). The endpoint answers only
the raw loopback peer, and refuses (404) any request that carries
`X-Forwarded-*` headers or a root-domain Host, i.e. anything that came
through Caddy; `/api/proxy/*` is not reachable through the root-domain
portal either. Certificates from this endpoint are not cached by Caddy, so
an upload, replacement or deletion applies to the next new TLS connection.
Caddy's in-memory cache is consulted first, though: if Caddy has already
loaded an ACME certificate for a name, it keeps serving that one until it is
restarted (`docker compose restart caddy`). The HTTPS portal on
`https://<root>/` is served by the same Caddy site, so it uses the uploaded
certificate as well.

#### Challenge (captcha gate)

Each entry has a collapsible **Challenge (ellenőrzés)** part on the Domainek
tab (`"challenge": {"triggers": [...], "interval_hours": n}` in the entry;
missing or empty = no challenge, the previous behaviour). The challenge is
evaluated only **after** authorization, i.e. only for a request that would be
let through (200); unauthorized requests still get the 401 page, and root
domains (the portal, which has its own captcha) are never challenged. When a
trigger fires, a page open gets a **403** page in the style of the denial
page, with `sus.png` and the same captcha as the login page ("Nem vagyok
robot" proof-of-work, or Turnstile when configured), and nothing else. After
a solved captcha the client gets a pass cookie and the page reloads. Other
requests (XHR, assets, API) get a short 403 JSON
(`"code": "proxy_challenge"`). Challenge 403s are not counted by fail2ban and
write no drop-log row.

Triggers:

- `always` (**Első megnyitáskor**): a valid pass is needed for the host; a
  pass lives 24 hours.
- `interval` (**X óránként**, `interval_hours` 1–720): a pass lives
  `interval_hours` instead of 24 hours.
- `daily` (**Naponta első megnyitáskor**): a pass issued before the last
  local midnight is no longer valid. The compose file mounts the host's
  `/etc/localtime` read-only, so the container uses the host's time zone
  (without it, UTC).
- `new_ip` (**Új IP-ről**): the pass is bound to the client IP it was issued
  to; without it the pass is bound only to the host, so it keeps working
  after an IP change.
- `after_401` (**Ha az IP kapott már 401-et**): only while the IP has a
  pending fail2ban proxy counter (401s or failed challenges within
  `proxy_window_seconds`; needs the proxy signal on); then the pass must have
  been issued after the IP's latest counted hit.
- `fail2ban` (**Ha bármely fail2ban-számláló fut rá**): the same with any
  pending counter (failed logins, dropped packets/ports, proxy 401s). A LAN
  client that keeps producing drops is challenged again after each new drop.
- `suspicious` (**Gyanús kliens**): the request has no `Accept-Language`, a
  page open has no `Sec-Fetch-Mode`, or the User-Agent is empty or a
  command-line client (curl, wget, python-requests, Go-http-client, ...);
  then any valid pass is enough.
- `burst` (**Sok frissítés / spam**): the same IP opened (refreshed) a page
  of the host 10 times within 30 seconds (counted only for page opens, in
  portal memory); then the pass must have been issued after that detection,
  and the counter starts again.

The first four impose a pass whenever they are set; the last four only
while their condition holds. The pass is the cookie `__Host-dropjak_pass`
(`Secure; HttpOnly; SameSite=Lax; Path=/`, no `Domain`, on the entry host),
value `base64url(host|ip or *|issued ms|expires).HMAC-SHA256`. The HMAC key
is random per portal process, so a portal restart invalidates every pass.
Caddy removes the cookie from the `Cookie` header before the request reaches
the upstream app (`header_up Cookie` regex replace).

The captcha is served through Caddy at `/__dropjak/challenge` on the entry
host (rewritten to the portal's `/api/gate/challenge`: `GET` issues a PoW
task or reports Turnstile mode, `POST {"captcha": ...}` verifies it with the
login code (signed, expiring, single-use PoW; Turnstile siteverify with the
client IP), checks the origin, applies the login rate limit, and sets the
cookie). It answers only the loopback peer and only for an enabled entry
with a challenge or a covered unknown subdomain; anything else is 404, and banned or proxy-banned IPs get
403. A failed verification counts as a proxy fail2ban hit. With Turnstile,
the site key must allow the entry hostnames. Audit: `proxy_challenge_shown`
(page opens only), `proxy_challenge_passed`, `proxy_challenge_failed`, with
`host` and the fired `triggers`.

Non-browser clients (API calls, webhooks, CLI tools) cannot solve the
challenge, so they get 403 whenever a trigger fires. Leave the triggers off
for API and webhook entries.

#### Unknown subdomains

A host `<anything>.<root>` under a configured root that is not an enabled
entry (unknown or disabled) is challenged when an unexpired **uploaded**
certificate of that root covers it (typically `*.<root>`):
`/api/proxy/cert` serves it by coverage, while `/api/proxy/ask` stays 404 for
it, so no ACME certificate is ever requested for such names (Let's Encrypt
rate limits). `/api/proxy/auth` then always answers with the challenge page
(403; non-navigation requests get the short 403 JSON), regardless of
triggers, session or pass; a banned IP gets a bare 403. After a solved
captcha `/api/gate/challenge` sets no pass and answers
`{"ok": true, "redirect": "https://<root>/"}`, and the page navigates to the
root portal. A failed verification counts as a proxy fail2ban hit. The audit
events are the same (`proxy_challenge_shown`/`_passed`/`_failed`) with
`host` and `unknown_host: true` instead of `triggers`. A name not covered by
an uploaded certificate is unchanged (404 / TLS handshake failure).

### Port proxy (TCP/UDP)

The **Proxy** admin tab forwards a TCP and/or UDP port of the firewall host
in the kernel (nftables DNAT), with no userland proxy process. The client IP
is preserved, and UDP works through conntrack, so it suits game servers such
as Minecraft (TCP 25565) and the Simple Voice Chat mod (UDP 24454).

Each entry has a label, protocol (`tcp`, `udp` or `both`), listen port, type,
target port, interfaces (`wan`, `lan` or `both`) and an on/off switch:

- **Forward** — `dnat` to a private IPv4 target (10/8, 172.16/12 including
  Docker bridge networks, 192.168/16). Access needs an active session whose
  **forward** rule lists the **listen port**: the forward chain matches
  `ct original ip saddr . ct original proto-dst` against
  `allowed_tcp`/`allowed_udp` (the same check as for published Docker ports)
  and sets the Docker guard mark, so a container target works too. Optional
  **SNAT** masquerades only that flow; use it when the target would not reply
  through the firewall (e.g. a LAN client to a LAN target). The target then
  sees the firewall's address instead of the client IP.
- **Input** — `redirect` to another port on the firewall host itself. Access
  needs a session whose **host (input)** rule lists the **listen port** (not
  the target port). The target port cannot be 22, 2019 or the portal port, and
  it cannot equal the listen port (a plain host rule does that).
  If the target port is bound **only to 127.0.0.0/8** (for example a Docker
  port published as `127.0.0.1:8081`), the rule is `dnat ip to
  127.0.0.1:<port>` instead, because `redirect` rewrites to the incoming
  interface address where nothing listens. This needs
  `net.ipv4.conf.all.route_localnet = 1` on the host (`docker/setup-host.sh`
  sets it; the portal container cannot, its `/proc/sys` is read-only). The
  `loopback_guard` chain (prerouting, priority raw, also in the boot table)
  drops every 127/8 destination or source arriving on a non-loopback
  interface. The portal re-checks the target sockets every 10 s and
  re-renders when the choice changes (e.g. Docker publishes after a reboot).
  A wildcard listener keeps `redirect`; a naive wildcard UDP server replies
  from the interface address, which a 127.0.0.1 DNAT would not match. A Docker
  container behind its 127.0.0.1 publication sees the docker-proxy address;
  use a Forward entry to the container IP when it needs the client IP.

Only traffic addressed to the host (`fib daddr type local`) on the chosen
interfaces is translated; a LAN client's traffic to an outside server on the
same port is not touched. Listen ports 22, 53, 67, 80, 443, 2019 and the
portal port are reserved, and a `(protocol, listen port)` pair can be used by
one entry only (`both` takes TCP and UDP). Tunnel services share this
listen-port namespace, and while an enabled tunnel agent exists its WireGuard
UDP port is reserved as well.

Order and precedence:

- The DNAT runs in its own `type nat hook prerouting priority -101` chain
  (`portproxy_prerouting` → `portproxy_nat`). The kernel runs nat chains by
  priority and stops at the first NAT binding, so on the chosen interfaces a
  Proxy entry wins over Docker's own DNAT (`ip nat PREROUTING`, priority
  -100) for the same published port. Saving such an entry is allowed but
  returns a warning, as does a port a local socket already listens on.
- Input-proxy packets go through `portproxy_input`, jumped from the input
  chain after the fail2ban drop, the block chain, the MAC checks and the
  proxy ban, but before the 80/443 proxy accept, the host-service guards and
  the established accept. An unauthorized redirected packet is dropped and
  logged as `reason=portproxy` (counts toward the drop-based fail2ban, like
  `no-grant`). Since every packet is checked, revoking the grant cuts open
  flows too. Unauthorized forward-proxy packets are dropped as `no-grant` /
  `wan-drop`.
- The forward chain's LAN MAC checks on port grants now apply to the
  original direction only (`ct direction original`), so replies from a LAN
  target are not checked against the client's MAC binding.

Saving applies the chains, `portproxy_snat` (jumped from postrouting) and the
other customized chains in one nft transaction, then writes
`firewall-settings.json` (`port_proxies`); on failure the previous rules are
restored. Changed, added or removed listen ports get their conntrack entries
flushed (`conntrack -D -p <proto> --orig-port-dst <port>`), so old flows do
not keep the old target. The runtime chains survive a template reload and are
re-applied at startup; an invalid settings file leaves them empty
(fail-closed). Changes are audited as `admin_portproxy_changed`. The new
chains appear in the raw firewall view.

**Minecraft + Simple Voice Chat example:** a `both` (or one TCP and one UDP)
forward entry for 25565 and 24454 to the server, and a forward rule that
allows TCP 25565 and UDP 24454. On the Minecraft server set `port=24454` in
`voicechat-server.properties`; if the public (listen) port differs, set
`voice_host=<public name>:<listen port>`.

### Tunnel agents (WireGuard)

The **Tunnels** block of Admin → Proxies and tunnels connects a private
Docker network behind NAT to the firewall without opening any port at home.
The host kernel must support WireGuard (module or built in, Linux 5.6+), and
the agent must be able to reach the firewall on the configured UDP port
(default 51820). If `tunnels.endpoint` is empty, the downloaded config uses
the hostname of the admin request (or `HV_PORTAL_URL`).

Creating an agent generates a server key pair (once), an agent key pair, a
preshared key, a `10.77.0.x` address and a random sync token. **Download
installer** produces a single self-extracting shell script; copy it to the
home host and run:

```bash
sudo sh dropjak-agent-<id>.sh
```

The installer is idempotent. On a TTY it lists the host's bridge networks and
joins the agent to exactly one of them (default `playitgg-net` when present);
non-interactively it uses `DROPJAK_NETWORK=<network>` or the same default. The
container is named `dropjak-tunnel-agent-<label-slug>-<id>` (also written to
`container-name`), so several agents can coexist on one host; each install
needs its own directory. `sudo sh dropjak-agent-<id>.sh delete` removes the
container and keeps the state volume.

Containment: the agent runs on exactly one normal bridge network with a
read-only root filesystem, `cap_drop: ALL` plus `NET_ADMIN`,
`no-new-privileges` and no host Docker/Podman socket. It resolves targets by
container name over that network's built-in DNS and can reach only containers
on it — no host gateway and no other network. Targets outside the attached
subnet are rejected fail-closed, and an agent failure keeps the last good
ruleset. `deploy/tunnel-agent/check-containment.sh` verifies the running
container and these settings from the home host.

A service maps one or more `proto`/`listen` ports to `target` ports (`tcp`,
`udp` or `both`; single ports, lists and ranges such as `8000-8100` are
accepted and paired by position), with a common target host (a container name
or IPv4 address). In port mode the internal tunnel port equals the listen
port. A **Test** button probes the full path (portal → WireGuard → agent
DNAT) mapping by mapping; the result is shown inline and disappears by
itself after 60 seconds, while editing, toggling or deleting the service
clears it immediately.

A **domain-mode service** replaces the mapping rows with a target host, a
`domain` and one target port. The domain must be a subdomain of a configured
root domain; the portal assigns the internal tunnel port automatically
(41000–60999) and Caddy serves the service over HTTPS. It has no WAN listen
port and no DNAT. Set its challenge triggers under Admin → Domains →
**Tunnel domains**, per service. A private domain service is admitted by a
**Domain (proxy)** rule listing its hostname or by a **Service** rule
referencing it; `public` makes it reachable without either. See
[Tunnels](DOKUMENTACIO.md#alagut) and
[Domain proxy](DOKUMENTACIO.md#domain-proxy).

### Backup

State is stored in the `hatarvedelem-state` volume
(`/var/lib/hatarvedelem`): `users.json`, `groups.json`, `rules.json`,
`audit.jsonl`, `drops.jsonl`, `fail2ban.json`, `firewall-settings.json` and the
uploaded proxy certificates under `certs/` (private keys included).
`firewall-settings.json` also holds the tunnel settings, including the
WireGuard server and agent private keys and the agent sync tokens, so treat
the backup as a secret.

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
installer copies the portal assets (`index.html`, `icon.png`, `blocked.png`,
`unauthorized.png`, `sus.png`, `ok.png`), `services.json` and `VERSION`, so
the portal serves its assets and `/api/status` reports the packaged version
instead of `0.0.0`. It also installs the `tunnel-agent/` bundle (compose
template, Dockerfile, agent and installer), so the agent installer can be
downloaded from a native installation as well.

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

The running version is stored in [`VERSION`](VERSION), and the release
history is recorded in the
[changelog](DOKUMENTACIO.md#valtozasnaplo). The portal footer shows the
version, and `GET /api/status` exposes the same value as `version`.

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
- The plain portal listens on HTTP. The optional Caddy domain proxy
  (`HV_PROXY=1`, see [Subdomain proxy](#subdomain-proxy-caddy)) serves the
  portal and proxy entries over HTTPS on the configured root domains, and
  sets the `Secure` session cookie there automatically. Without it, if the
  portal is reachable from an untrusted network, terminate TLS in front of it
  and set `HV_COOKIE_SECURE=1`; otherwise restrict `HV_PORTAL_NET` to a
  trusted management network. The plain-HTTP port and the LAN captive path
  remain cleartext, so credentials and session cookies can be sniffed there.
- TOTP 2FA does not make the plain-HTTP portal confidential. The base32
  secret and `otpauth://` URI are displayed and transmitted in cleartext, and
  6-digit and recovery codes are sent in request bodies; anyone who can sniff
  the LAN can capture them. `HV_COOKIE_SECURE=1` protects only the cookie.
  Restrict `HV_PORTAL_NET` to a trusted network. Integrated HTTPS termination
  now exists through the optional Caddy domain proxy (`HV_PROXY=1`, see
  [Subdomain proxy](#subdomain-proxy-caddy); the original plan is archived
  under [Caddy proxy plan](DOKUMENTACIO.md#caddy-proxy-terv)), but it covers
  only the root-domain HTTPS portal and proxy entries, not the plain-HTTP
  portal on port 8100 or the LAN captive path.
- TOTP secrets are stored unencrypted in `users.json` (mode `0600`) in the
  state volume. Protect the volume and its backups accordingly.
- A downloaded tunnel installer and its `agent.json` contain the agent's
  WireGuard private key, preshared key and sync token; treat the file as a
  secret and remove it after installation if it is no longer needed. The sync
  endpoint accepts only the agent's tunnel source address together with that
  token. The agent can reach every container on its single attached bridge
  network, so attach it only to the network whose services you intend to
  expose; `check-containment.sh` verifies the isolation settings.
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
