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
  `banned_v4` set and its packets are dropped. The portal (and DHCP) remain
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

The **Drop log** admin tab shows packets the firewall dropped, with filters
for source/destination, protocol, port, reason and free-text search. Entries
are written to `drops.jsonl` in the state volume and rotate at 10 MiB (5
files kept). The log is captured through NFLOG (`nfnetlink_log`) on group 5;
the kernel must support NFLOG, and the group must not be used by another
process. Only packet headers are stored, never payloads.

The **Fail2ban** admin tab protects the portal login. Failed passwords are
counted per source IP; after the configured number of attempts within the
window, the IP is banned for the configured duration. The tab shows the
status, the active bans with a live countdown, and the pending attempts. Any
IP can also be banned or unbanned manually, and a ban can be lifted before it
expires. The threshold, window and ban duration are editable at runtime; the
`HV_FAIL2BAN*` variables only provide the initial defaults. Bans are written
to `fail2ban.json` (mode `0600`) and restored on start, and every ban is also
recorded in the drop log with reason `fail2ban`.

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
  entries also skip the captive-portal redirect.
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
  the ban expires. A manual ban can lock out your own management IP; the
  portal stays reachable from that IP so you can sign in and lift the ban,
  and the CLI commands above work from the host console. Treat the threshold
  and ban duration as a trade-off: a very low threshold makes it easy to lock
  out legitimate clients behind a shared NAT address.
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
