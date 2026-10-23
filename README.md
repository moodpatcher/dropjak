<p align="center">
  <img src="icon.png" alt="dropjak" width="160">
</p>

# dropjak

Fail-closed captive-portal firewall for Linux. Every client is blocked by
default: after signing in, the client picks one or more access rules and a TTL
(up to 30 days), and only those ports and services open for that IP. Logout,
expiry or revocation closes access immediately. nftables under the hood, Docker
host networking, portal in Hungarian, English and German.

## Features

- **Fail-closed forwarding** — no grant, no traffic; revocation closes established flows.
- **Two-phase login** — password plus optional TOTP, then explicit rule and TTL selection.
- **Forward and host (input) rules**, plus collection rules (up to 64 members).
- **Multi-rule grants** — up to 16 assigned rules at once, with *Select all* and *Max*.
- **Gated host SSH** — TCP 22 opens only for an authorized session from the same IP.
- **MAC binding** — every grant is tied to the client's IP and ARP-resolved MAC.
- **Fail2ban** — failed logins, drop/port metrics and proxy 401 signals, persistent bans.
- **Drop log and audit log** — NFLOG-captured drops plus a filterable event history.
- **TOTP 2FA** — QR enrollment, single-use recovery codes, admin reset.
- **Subdomain proxy** (optional Caddy) — automatic HTTPS, captcha challenges, uploaded certificates.
- **Port proxy** — nftables DNAT for TCP/UDP, no userland proxy process.
- **Tunnel agents** — expose NATed home containers over WireGuard; port- and domain-mode services.
- **Domain rules** — grant proxy hostnames without opening any firewall port.
- **Admin UI and CLI helpers** for users, rules, sessions and fail2ban.

## Installation

Docker only. You need a Linux host with nftables and NFLOG, Docker Engine plus
Compose v2, one LAN-facing and one WAN-facing interface, and
`net.ipv4.ip_forward=1`.

1. **Clone the repository.**

   ```bash
   git clone https://github.com/moodpatcher/dropjak.git
   cd dropjak
   ```

2. **Prepare the host.** Blocks forwarding before Docker starts and persists
   `ip_forward`; it does not touch SSH.

   ```bash
   sudo ./docker/setup-host.sh
   ```

3. **Configure.** Fill in the required values and create the first admin
   (without an admin account the portal is unusable and host SSH stays closed).

   ```bash
   cp .env.example .env
   chmod 600 .env
   ```

   ```ini
   HV_LAN_IF=eth1            # clients
   HV_WAN_IF=eth0            # internet
   HV_LAN_NET=192.168.10.0/24
   HV_PORTAL_NET=0.0.0.0/0   # source networks allowed to reach the portal
   HV_ADMIN_ENABLED=1
   HV_ADMIN_USER=admin
   HV_ADMIN_PASSWORD=<long-random-password>
   ```

4. **Start the stack.**

   ```bash
   docker compose up -d --build
   ```

   Open `http://<lan-ip>:8100/`.

> **Lockout warning.** Loading the firewall cuts host SSH. TCP 22 is reachable
> only from an IP with an authorized portal session and an explicit TCP 22
> input rule, so keep the provider console available.

Optional HTTPS proxy: set `HV_PROXY=1` and `COMPOSE_PROFILES=proxy`, then run
`docker compose up -d` and add the domain under **Admin → Domains**.

Configuration reference, operations, security notes and the changelog live in
[DOKUMENTACIO.md](DOKUMENTACIO.md).
