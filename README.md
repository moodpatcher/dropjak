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

2. **Configure first — this is the last step that does not touch the
   firewall.** Create the network settings and the first admin. Without an
   admin account the portal is unusable, and once the firewall loads there
   is no way back in over SSH.

   ```bash
   ./configure.sh
   ```

   It lists the interfaces, asks which one is the LAN and which one is the
   WAN, then the networks, the portal port and the admin account (leave the
   password empty to generate one), and writes `.env` with mode 0600.
   Re-running it keeps the current values as defaults. The portal is
   **public by default** (`HV_PORTAL_NET=0.0.0.0/0`); give a management CIDR
   if it should not be reachable from the internet.

   ```ini
   HV_LAN_IF=eth1            # clients
   HV_WAN_IF=eth0            # internet
   HV_LAN_NET=192.168.10.0/24
   HV_PORTAL_NET=0.0.0.0/0   # source networks allowed to reach the portal
   HV_ADMIN_ENABLED=1
   HV_ADMIN_USER=admin
   HV_ADMIN_PASSWORD=<long-random-password>
   ```

3. **Prepare the host.** Blocks forwarding before Docker starts, persists
   `ip_forward`, and activates the early boot protection, which closes host
   SSH (TCP 22) for every source except the SSH session that started the
   script. That session stays reachable until the container loads its rules.

   ```bash
   sudo ./docker/setup-host.sh
   ```

4. **Build the image, then start the stack.** The build must run on the host
   network: the fail-closed forward chain blocks the build container's egress,
   so apt-get cannot reach the Debian mirrors from Compose's bridge.

   ```bash
   DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .
   docker compose up -d
   ```

   Open `http://<lan-ip>:8100/`, sign in with the admin account from `.env`,
   change the password, then create and assign a **Host SSH** input rule
   (TCP 22) if you need SSH.

> **Lockout warning.** The first container start closes host SSH: TCP 22 is
> reachable only from an IP with an authorized portal session and an explicit
> TCP 22 input rule. Keep the provider console available.

Optional HTTPS proxy: set `HV_PROXY=1` and `COMPOSE_PROFILES=proxy`, then run
`docker compose up -d` and add the domain under **Admin → Domains**.

## Updating

In the checkout, in two steps:

```bash
sudo ./update.sh --yes      # backup, then git pull --ff-only
sudo ./deploy/hv rebuild    # rebuild the image and recreate the containers
```

`update.sh` deliberately does not deploy: it only makes a backup and pulls the
code. `deploy/hv rebuild` is the step that applies it (it runs
`DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .` and
`docker compose up -d --force-recreate`).

> **Run the rebuild from the provider console, not over SSH.** The recreate
> flushes the dynamic nftables sets, `allowed_input_tcp` included, so host SSH
> closes in the middle of the command. A rebuild started from an SSH session
> dies with the connection and can leave the stack half-recreated while the
> fail-closed table is still loaded. After the rebuild, sign in on the portal
> and re-authorize SSH (an explicit TCP 22 host rule is still required).

To go back, `./restore.sh` lists the backups (`.manifest` files in
`/root/dropjak-backups`) and returns the checkout, the state and the previous
image to the chosen point.

Configuration reference, operations, security notes and the changelog live in
[DOKUMENTACIO.md](DOKUMENTACIO.md).
