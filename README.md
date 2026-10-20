<p align="center">
  <img src="icon.png" alt="dropjak" width="180">
</p>

# dropjak

dropjak is a captive-portal firewall for Linux. It runs as a Docker
container in host network mode and controls the host's nftables forwarding
plane. All client traffic is **blocked by default**: a client gets network
access only after signing in through the portal and choosing an access rule
and a TTL (1 minute to 24 hours). Only the ports and services allowed by that
rule are opened for the client's IP address. Logout or expiry revokes access
immediately.

The portal is available in Hungarian, English and German. It follows the
system light/dark preference and the theme can be switched manually in the
bottom-right corner.

## How it works

- The `forward` chain is fail-closed; the portal is the only publicly
  reachable service.
- A correct password alone does not grant network access. Sign-in is
  two-phase: authenticate, then explicitly select an access rule and TTL.
- Account requests are optional and off by default. When an admin enables
  **Fiókkérelmek** in **Admin → Settings**, the login page shows **Fiók
  kérése** and a visitor can submit a username, password and email after the
  usual captcha. This creates a pending, disabled account with no rules or
  access; an admin approves or rejects it in **Admin → Users**. The email is
  stored as contact data only and is never sent or logged.
  See [docs/account-requests.md](docs/account-requests.md).
- Grants are implemented with nftables dynamic sets (`allowed_v4`,
  `allowed_tcp`, `allowed_udp`, `allowed_icmp`, `host_ssh_v4`, `client_mac`).
  Entries expire in the kernel even if the portal stops.
- Each grant is bound to the client's IP **and MAC address**. The MAC is read
  from the host ARP table at authorization time; if it cannot be resolved,
  access is refused. Source-IP spoofing and DHCP lease takeover alone do not
  inherit an existing grant.
- Host SSH is also gated: by default only an IP with an active, authorized
  **admin** portal session can connect to port 22 (`HV_HOST_SSH=admin`; use
  `any` or `off` to change the policy).
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
- Every restart flushes the dynamic sets; users must sign in again. Persistent
  state (users, groups, rules, audit log, bans) lives in a Docker volume.
- The container uses `network_mode: host` because the host's `forward` chain
  cannot be managed from a Docker bridge namespace. Only one instance can run.

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

The `otpauth://` issuer/label defaults to `Dropjak`; set `HV_TOTP_ISSUER` to
change it (see `.env.example`).

TOTP only creates the portal session. Network access still requires the
second phase: select an access rule and TTL, then authorize the grant. The
second factor alone does not open the firewall.

## Operations

### Update

```bash
git pull
docker compose up -d --build
```

The entry point reloads the firewall rules idempotently. On portal start the
dynamic sets are flushed (`HV_FLUSH_ON_START=1`), so every user has to sign in
again. State in the Docker volume is preserved.

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
DNS (TCP 53) and the portal port are ignored. Drop banning has its own
enable switch, thresholds and window (`drop_enabled`, `drop_max`,
`drop_ports`, `drop_window_seconds`, or `HV_FAIL2BAN_DROP*`), all editable
in the admin tab; it reuses the login ban duration. The pending drop events
are listed separately, and a drop-based ban is marked `drop` in the ban
list and on the ban screen.

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

### Firewall customization

The **Settings** admin tab manages three things:

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
- **Block rules** — destination/ports that are always dropped. The block is
  evaluated before pre-auth, so it overrides a pre-auth entry.
- **Host SSH policy** — `admin`, `any` or `off`, applied immediately.
  Narrowing the policy revokes SSH access for sessions that no longer
  qualify.

Changes are validated, applied to nftables, and only then written atomically
to `firewall-settings.json`; if the nftables update fails, the previous rules
are restored. Invalid or corrupted settings fall back to an empty pre-auth
list (fail-closed).

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

## Security notes

- Forwarding is fail-closed. If the portal or Docker fails to start, traffic
  stays blocked.
- Host SSH is opened only for the source IP of an active, authorized portal
  session, and by default only for admin sessions. Always keep an out-of-band
  console (provider console) available so you can recover if the portal does
  not start.
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
