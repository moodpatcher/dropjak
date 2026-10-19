<p align="center">
  <img src="icon.png" alt="Dropjak" width="180">
</p>

# Dropjak

Dropjak is a captive-portal network gateway for Linux. It runs as a Docker
container in host network mode and controls the host's nftables forwarding
plane. All client traffic is **blocked by default**: a client gets network
access only after signing in through the portal and choosing an access rule
and a TTL (1 minute to 24 hours). Only the ports and services allowed by that
rule are opened for the client's IP address. Logout or expiry revokes access
immediately.

The portal is available in Hungarian, English and German.

## How it works

- The `forward` chain is fail-closed; the portal is the only publicly
  reachable service.
- A correct password alone does not grant network access. Sign-in is
  two-phase: authenticate, then explicitly select an access rule and TTL.
- Grants are implemented with nftables dynamic sets (`allowed_v4`,
  `allowed_tcp`, `allowed_udp`, `allowed_icmp`, `host_ssh_v4`). Entries expire
  in the kernel even if the portal stops.
- Host SSH is also gated: only an IP with an active, authorized portal
  session can connect to port 22.
- Docker-published containers work too: forward rules match the pre-DNAT
  destination port, so the grant reaches the container.
- Every restart flushes the dynamic sets; users must sign in again. Persistent
  state (users, groups, rules, audit log) lives in a Docker volume.
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
http://<gateway-lan-ip>:8100/
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

### Backup

State is stored in the `hatarvedelem-state` volume
(`/var/lib/hatarvedelem`): `users.json`, `groups.json`, `rules.json` and
`audit.jsonl`.

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
  session. Always keep an out-of-band console (provider console) available so
  you can recover if the portal does not start.
- Keep `.env` at mode `0600`; it may contain the admin password. Never commit
  it. `.secret` and state files are excluded by `.gitignore`.
- `docker compose down` leaves the `inet hatarvedelem` nftables table in place
  (fail-closed). Remove it explicitly if you want to tear the gateway down:
  `sudo nft delete table inet hatarvedelem`.
- If `firewalld` or `ufw` is active on the host, verify that it does not
  conflict with the gateway's forward rules. A dedicated gateway VM is
  recommended.
