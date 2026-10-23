# Dropjak — documentation

This file unifies all Markdown documentation of the project, with the exception of `README.md`, which remains separate and unchanged. The merge took place on 2026-10-22; at the beginning of each section an italic line indicates which original file the content comes from (the original files can be found in the git history). The heading levels were shifted (the original H1 became the section title) and the links between documents point to the anchors of this file. The whole document was translated into English on 2026-10-23; quoted UI labels keep their original Hungarian wording, while API validation messages and log strings are shown in the English form the server emits. Code blocks, tables and `file:line` references are otherwise unchanged, and the original Hungarian text remains available in the git history.

## Contents

1. [Project status](#projekt-allapot)
2. [Installation and operations](#telepites)
3. [Features](#funkciok)
   1. [Account requests](#fiokigenyles)
   2. [TOTP two-factor authentication](#totp-2fa)
   3. [Host (input) rules](#host-szabalyok)
   4. [Collection rules and rule duplication](#gyujtoszabalyok)
   5. [Propagation matrix](#propagacios-matrix)
   6. [Audit log](#audit-naplo)
   7. [Post-login notice (MOTD)](#motd)
   8. [Tunnels](#alagut)
4. [Domain proxy](#domain-proxy)
   1. [Plan: Caddy reverse proxy and automatic TLS](#caddy-proxy-terv)
   2. [Development and deployment log](#domain-proxy-naplo)
5. [Security review (2026-10-21)](#biztonsagi-atvizsgalas)
6. [Plans and archive](#tervek-archivum)
   1. [Anti-slop plan (2026-10-20)](#antislop-terv)
   2. [Design snapshot: notes](#design-backup-notes)
   3. [Design snapshot: README copy](#design-backup-readme)
7. [Changelog](#valtozasnaplo)

<a id="projekt-allapot"></a>

## 1. Project status

_Source: `PROJEKT-ALLAPOT.md` (original title: "Dropjak / hatarvedelem — project status")._

**Document date:** 2026-10-22
**Live version:** 3.24.0 · **Local working directory:** 3.24.0
**Live test environment:** see the private operations notes (not in this repository).
**This document:** a local, contiguous state snapshot; not an installation guide and not a commit.

### How to read this document
This description distinguishes three kinds of status and marks them in the text:

| Marker | Meaning |
|---|---|
| **LIVE** | On the test VM the 3.24.0 image runs, and the given behavior is available according to the specified snapshot. |
| **LOCAL CODE** | It is described by the source in the local working directory; its appearance on the running VM is not necessarily separately verified. |
| **PLAN / DEFERRED** | An intention, document or `todo.txt` item; not implemented or not live. |
| **NOT VERIFIED** | Cannot be unambiguously determined from the available files; I do not state it as certain fact. |

The document does not contain or quote secrets: there is no `.env` content, password, password hash, TOTP secret or code, token, cookie, recovery code or personal IP address. Operational details (addresses, paths, backup names, image digests) are kept out of this public document.

Where the text refers to a file or behavior, the source is the local repository. Where it describes live status, that is a fact of the 2026-10-21 snapshot. Where the two may differ, I indicate it separately.

### 1. Executive summary
The Dropjak is a Linux captive-portal-type network entry gateway. The network is **closed** by default: a client receives traffic only after logging in on the portal and then, in a second step, selecting one or more access rules and a duration specified in whole hours. The authorization is bound to the client's IPv4 address and MAC address and is implemented via a kernel-side nftables set. On expiry or logout the access ceases.

The system's main characteristics:

- **Fail-closed forward chain.** If the portal or Docker does not start, forwarded traffic remains blocked.
- **Two-phase login.** The password (and captcha) alone does not open the network; a separate `POST /api/access` request and rule selection are required.
- **Dynamic nftables sets.** Authorizations expire in the kernel even if the portal stops.
- **Directional rules.** `forward` (internet, Docker-published service) and `input`/host (service running on the portal machine) rules.
- **Multiple rule selection.** A session can select several rules; the union is calculated per direction, and the TTL is adjusted to the strictest `max_ttl`.
- **Partial revocation.** When a rule is modified, only the affected selection and its exact kernel elements disappear.
- **MAC binding and anti-spoofing.** The source IP alone cannot be inherited.
- **Host SSH only through the portal.** This requires a host rule created by an admin that explicitly includes TCP 22, and an active, authorized session.
- **fail2ban.** It bans based on three independently switchable signals: failed logins, dropped packets and distinct destination ports. Thresholds cannot be 0.
- **Logging.** JSONL audit log (event, severity, redaction) and NFLOG-based drop log.
- **TOTP 2FA.** Optional, with QR-code enrollment, recovery codes, in-memory tickets.
- **Trilingual portal.** Hungarian, English, German; light/dark theme.

The live version is 3.3.0. The 3.3.0 fail2ban refactor (fully independent switching of the three signals, removal of the 0 threshold, migration of saved 0 values, and removal of the drop master switch) is on the VM; the recreate that installed it closed host SSH because the dynamic sets were flushed. The local working directory contains 3.3.1 (fixes from independent verification: the location of the shared ban length, the English/German validation message, saving an empty/disabled field, the audit breakdown and stronger tests), which is not yet deployed. Multi-selection was checked manually, live (`ssh,mpwerks`), but the automated `HV_E2E_MULTI` K6 scenario has not yet run live.

### 2. Current live status

_This section records the live snapshot of 2026-10-21; the document header and the
3.24.0 sections describe the local state of 2026-10-22._

#### 2.1. Environment
| Property | Value | Status |
|---|---|---|
| Operating system | Debian 13 | LIVE (snapshot) |
| Docker Engine | 26.1.5 | LIVE (snapshot) |
| State | Docker volume (`dropjak-state`) | LIVE |
| Portal | `http://<test-vm>:8100/` | LIVE, HTTP 200 |
| API | `/api/status` → `ok: true`, `version: 3.3.0` | LIVE |
| Container uptime / container ID | not present in the snapshot | NOT VERIFIED |

The portal runs in the host's network (`network_mode: host`), so port `8100` listens on the host and there is no Docker `ports:` mapping. The container's root filesystem is read-only; state is in the separate volume.

#### 2.2. Installation and restorability
Backups exist on the VM; their names and paths are in the private operations notes.

The deploy script and the log serve the reproducibility of the installation process. The contents of the backups were not unpacked at file level in this session: it is **NOT VERIFIED** exactly which state files the two archives contain and from what point in time.

Integrity observation before the recreate:

- the `.env` md5 is unchanged (this document intentionally does not include the value);
- on the VM the `.secret` file did not exist.

The `.env` content was not read and is not included in this document. The integrity observation above only indicates that the installation did not overwrite the environment file.

#### 2.3. Known live behavior
- After the 3.3.0 installation **host SSH remained closed**. The reason is by design: during the recreate the dynamic nftables sets were flushed, including `allowed_input_tcp`, so the previous `(IP, 22)` authorization disappeared. Re-authorization happens on the portal, from the same public IP.
- The portal is reachable from the browser, the `/api/status` response is `ok: true`, the version is `3.3.0`.
- The live manual check of multiple rule selection was performed with the `ssh` and `mpwerks` rules.
- The automated live multi K6 run has not taken place.
- The local full test suite in the 3.24.0 working directory is **985 tests OK**, and the syntax check of the portal's inline JavaScript is OK.

#### 2.4. Working directory state
The git state according to the snapshot is not clean: there are several modified files and several new, not yet tracked test/documentation files. This is not necessarily an error: some of the 3.3.0 changes may be in the local working directory while the running image already contains them; the 3.3.1 fixes, however, exist only locally. The commit/push state and the bit-for-bit identity of the local and live code are **NOT VERIFIED**.

### 3. Architecture
#### 3.1. Runtime components
```text
Browser (client)
    |
    | HTTP :80 / :8100
    v
+----------------------------- host, inet hatarvedelem -----------------------------+
|  nftables: prerouting (redirect), forward (policy drop), input (policy drop)     |
|  dynamic sets: allowed_v4, allowed_tcp, allowed_udp, allowed_input_tcp,          |
|  allowed_input_udp, allowed_icmp, client_mac, banned_v4                          |
|  static guard sets: host_service_tcp, host_service_udp                           |
+------------------------------------+-----------------------------------------------+
                                     |
                                     | nft / conntrack / ARP
                                     v
+---------------------------- Docker container (host network) ----------------------+
|  docker/entrypoint.sh                                                             |
|    - rendering and loading the template                                            |
|    - flushing dynamic sets at startup                                              |
|    - deleting the boot table, Docker DOCKER-USER guard, watchdog                   |
|    - setpriv → hatarvedelem user                                                   |
|  server.py  ── HTTP API, portal, admin, auth, session cookie                      |
|  gateway.py ── rules, sessions, nft calls, revocation, TTL                         |
|  fail2ban.py ── login- and drop-based banning, persistence                        |
|  droplog.py ── reading NFLOG group 5, drops.jsonl, rotation                        |
|  settings_store.py ── validation of pre-auth/block/site settings, atomic write     |
+------------------------------------------------------------------------------------+
```

The container does not operate in its own network namespace: it must reach the host's `forward` chain, hence `network_mode: host`. For this reason only one instance can run on a host, and the portal listens on the host's `PORT` (by default `8100`).

#### 3.2. Responsibilities
| Component | Responsibility |
|---|---|
| `server.py` | HTTP server, routes, JSON validation, origin checking, auth, admin operations, static `index.html`, `icon.png`, `blocked.png`. |
| `gateway.py` | `Rule`, `RuleSelection`, `Ports`, `Session`, `SessionManager`; writing the nft sets, conntrack deletion, revocation, expiry, startup reconciliation. |
| `fail2ban.py` | Counting failed logins and drop events; writing `banned_v4`; persisted `fail2ban.json`; runtime configuration. |
| `droplog.py` | Reading the NFLOG netlink group, writing drop records to JSONL, rotation, filtering, merging fail2ban events. |
| `settings_store.py` | Validation and atomic, fault-tolerant writing of `firewall-settings.json`; pre-auth/block/site fields. |
| `docker/entrypoint.sh` | First start order, env validation, nft loading, flushing dynamic sets, Docker guard, watchdog, privilege dropping. |
| `install.sh` | Native, systemd-based installation; copying files, filling placeholders, units and drop-in. |
| `configure.sh` | Interactive `.env` generator for the Docker installation (interfaces, networks, portal exposure, first admin account). |
| `deploy/hv` | Docker operational helper (status, logs, restart, rebuild, backup, test, e2e). |
| `index.html` | Complete single-page portal and admin UI, in three languages. |

#### 3.3. Startup sequence
1. On the host, `dropjak-boot.service`, installed by `docker/setup-host.sh`, loads early a separate `inet hatarvedelem_boot` table: `forward` policy drop, and blocking host SSH (`tcp dport 22`) until the final rules are loaded.
2. The Docker daemon starts, then the container.
3. `entrypoint.sh` refuses to start when `HV_PROXY=1` and `HV_PROXY_KEY` is shorter than 32 characters (before touching the firewall; the error says to run `openssl rand -hex 32`). The mandatory env values are `HV_WAN_IF` and, in the default two-NIC mode, `HV_LAN_IF` and `HV_LAN_NET`; with `HV_SINGLE_NIC=1` the latter two are ignored. `HV_PORTAL_NET` defaults to `0.0.0.0/0` (public portal). It renders the template, and loads the `inet hatarvedelem` table.
4. The entrypoint flushes the dynamic sets so that no authorization remains without a session. `host_service_tcp` / `host_service_udp` are intentionally not flushed.
5. It deletes the former `host_ssh_v4` set if it still exists; it can no longer grant access.
6. It deletes the early boot table.
7. It fills the `docker_bridges` set with the host's bridge interfaces (`ip -o link show type bridge`, without `HV_LAN_IF` and `HV_WAN_IF`), then checks and, if necessary, installs the Docker `DOCKER-USER` guard. If no guard can be installed (no `DOCKER-USER` chain, or Docker's nftables firewall backend), it logs an `ERROR` line and keeps starting: stopping would leave the host in a crash loop behind the boot table.
8. It starts the watchdog (every 5 s: reloads a lost or incomplete table, refreshes `docker_bridges`, reinstalls a missing guard, and repeats the guard `ERROR` at most once a minute), then switches to the `hatarvedelem` user with `setpriv` and runs `server.py`.
9. On startup `server.py` loads the rules, users, groups, settings, fail2ban state, and if needed reconciles the kernel sets to the empty session table.

`HV_SKIP_FIREWALL=1` skips nft loading, the Docker guard and the watchdog. This is **not secure**, only a developer or emergency opt-in.

### 4. Network and firewall model
#### 4.1. Tables and chains
| Object | Type | Role |
|---|---|---|
| `inet hatarvedelem` | table | The final rules. |
| `forward` | filter, priority `-10`, policy `drop` | All forwarded traffic is blocked by default; it runs before Docker's FORWARD chain. |
| `input` | filter, policy `drop` | Traffic toward the host; portal, DHCP/DNS, host rules. IPv6 is dropped right after the loopback accept, before `breakglass`. |
| `prerouting` | nat, priority `dstnat` | HTTP → portal redirect, pre-auth/block NAT exceptions. |
| `postrouting` | nat, priority `srcnat` | NAT additions. |
| `preauth` | custom | Forward destinations/ports reachable before login (LAN, or DNATed WAN traffic). |
| `preauth_input` | custom | Host (input) ports reachable before login; runs after `block`, before the portal and SSH rules. |
| `block` | custom | Always-blocked destinations/ports; runs before every authorization. The forward chain jumps to it unconditionally, the input chain only for original-direction traffic from `HV_LAN_IF`. |
| `preauth_nat` | custom | Pre-auth TCP 80 bypasses the portal redirect. |
| `block_nat` | custom | Drops blocked TCP 80 already before the redirect. |
| `breakglass` | custom | Emergency SSH rule; the template does not flush it, empty by default. It runs after the IPv6 drop, so it cannot open IPv6. |
| `loopback_guard` | filter, priority `raw` (prerouting), policy `accept` | Drops 127/8 sources/destinations and **every IPv6 packet** arriving on a non-loopback interface, before NAT and conntrack. |
| `inet hatarvedelem_boot` | table | Early boot protection before Docker starts; the container deletes it. |

The template is idempotent: flushing and rebuilding the chains happens in one nft transaction, and it does not touch the dynamic sets. Thus an `nft -f` reload does not log out clients, but when the container starts the entrypoint separately, deliberately flushes the dynamic sets.

#### 4.2. Dynamic sets
| Set | Key | Size | Role |
|---|---|---|---|
| `allowed_v4` | `ipv4_addr` | 4096 | Full-access client IPs. |
| `allowed_tcp` | `ipv4_addr . inet_service` | 16384 | Forward TCP destination ports per client; `interval,timeout`, with range elements. |
| `allowed_udp` | `ipv4_addr . inet_service` | 16384 | Forward UDP destination ports per client; `interval,timeout`. |
| `allowed_input_tcp` | `ipv4_addr . inet_service` | 16384 | Host TCP ports per client, `interval,timeout`; the `(IP, 22)` SSH authorization also lives here. |
| `allowed_input_udp` | `ipv4_addr . inet_service` | 16384 | Host UDP ports per client, `interval,timeout`. |
| `allowed_icmp` | `ipv4_addr` | 4096 | ICMP echo authorization. |
| `client_mac` | `ipv4_addr . ether_addr` | 4096 | The MAC pinned to the authorized IP. |
| `banned_v4` | `ipv4_addr` | 4096 | Sources banned by fail2ban. |
| `host_service_tcp` | `inet_service` | 65536 | `interval`; add-only: every host TCP port/range ever declared. |
| `host_service_udp` | `inet_service` | 65536 | Same for UDP, with the `interval` flag. |
| `docker_bridges` | `ifname` | — | Bridge interfaces not named `docker*`/`br-*` (custom Docker bridge names, other host bridges); filled by the Docker entrypoint and its watchdog, never by the template. Empty on a native install. |

The port-based dynamic sets have the `interval,timeout` flag: a rule can also give a port range (`8000-8100`), which enters the kernel as a single nft element. `auto-merge` cannot be used alongside timeout, so `gateway.py` merges and splits overlapping ranges during grant/revoke operations; partial revocation puts the remaining part back with the remaining TTL. The `host_service_*` sets are `interval`-flagged, permanent, grow-only guard sets: their job is to cut off the established connection of a revoked host access even if conntrack flushing fails or the kernel revives the flow.

#### 4.3. Order of traffic decisions
The approximate order of the forward chain:

1. IPv6 drop (closed despite IPv4 forwarding; the raw prerouting `loopback_guard` already dropped it).
2. Source IP spoofing prevention: on the LAN interface only `HV_LAN_NET`, from the WAN a LAN source is forbidden (two-NIC mode; in single-NIC mode there is no LAN-scoped spoof rule).
3. `banned_v4` drop, logged; this runs before every authorization and pre-auth.
4. MAC check for authorized IPs on the LAN (two-NIC mode; disabled in single-NIC mode).
5. `block` chain; the block precedes every grant. Then the link-local (`no_forward_v4`) drop, and the DNAT requirement: a new flow into `docker*`, `br-*` or a `docker_bridges` interface, or from the WAN into the LAN, is dropped unless it was DNAT-ed (published port, port proxy). The WAN→LAN guard is omitted in single-NIC mode.
6. Full access (`allowed_v4`) and port authorizations (`allowed_tcp`, `allowed_udp`, `allowed_icmp`), with `meta mark set 0x44524a4b`.
7. The response direction of full access and ICMP with the mark; the response of port authorizations is covered by matching according to `ct original`.
8. Docker container exceptions (in the template `172.30.0.2`): anti-spoof and LAN-pivot blocking, DNS and 53/80/443 egress, and responses to connections initiated by the container.
9. `preauth` chain; pre-auth means bypassing the portal, and it also covers the response direction.
10. Everything else drop.

The input chain is similarly fail-closed, but with the portal and, in two-NIC mode, DHCP and LAN DNS as exceptions. Host SSH is opened by the `(IP, 22) ∈ allowed_input_tcp` pair; the generic established rule does not keep revoked SSH alive. The input `block` jump is `iifname "<HV_LAN_IF>" ct direction original jump block` in two-NIC mode: block entries restrict the LAN clients, so a destination-less entry (for example TCP 443) does not stop inbound WAN traffic to the host (Caddy, tunnels, port proxies), nor replies to the host's own connections. In single-NIC mode the LAN input block jump is omitted entirely, so block entries never cut WAN input traffic; they stay forward-only. There is no post-DNAT matching. After the `block` jump, but before the MAC guards, the portal and SSH rules, `jump preauth_input` follows: this implements the `input` direction of `preauth` entries, with direct `accept` (no forward mark and no `preauth_nat`). The chain starts with the `banned_v4` drop and matches traffic by `ct original ip daddr`/`ct original proto-dst`. The entry's `scope` decides the interfaces: `lan` (the default, also for entries stored without the field) renders only `iifname "<HV_LAN_IF>"`, including its established accept; in single-NIC mode `lan` uses `HV_WAN_IF` instead. `any` renders the LAN and the WAN interface and an interface-free established accept. A `lan` entry without a known LAN interface is skipped with a warning; if neither interface is known, rendering stops with an error.

#### 4.4. Portal and captive portal
The HTTP traffic of an unauthorized client is redirected by the prerouting chain to the portal. The portal is always reachable from the LAN; access from the WAN depends on the value of `HV_PORTAL_NET`. The `block` and `preauth` rules look at the pre-DNAT (original) destination, so for a Docker-published service the VM's public address and the published host port must be used, not the container's internal address. Pre-auth in the `input` direction intentionally does not get a `preauth_nat` exception: TCP 80 from the LAN is still redirected to the portal, while the host port from the WAN is directly reachable.

#### 4.5. Docker integration
The forward rules put `meta mark set __FWD_MARK__` on forwarded packets. The guard installed in the `DOCKER-USER` chain allows only marked packets through and drops everything else. If the `inet hatarvedelem` table disappears, Docker cannot open a bypass. A marked packet toward a container bridge (`docker*`, `br-*`, and every name in `docker_bridges`) is not accepted in `DOCKER-USER`; it continues to Docker's own isolation rules.

Custom bridge names (`com.docker.network.bridge.name`) need no naming rule: the entrypoint reads every bridge interface at startup, and the watchdog refreshes `docker_bridges` and the `DOCKER-USER` accept when a network is created or removed. The LAN and WAN interfaces are never in the set, even if they are bridges. Docker's nftables firewall backend has no `DOCKER-USER` chain; then, or when the chain is missing for any other reason, the container keeps running and logs `ERROR: Docker forward protection is NOT installed` at start and at most once a minute. Published ports are then guarded only by the `inet hatarvedelem` table (its forward drops cannot be overridden by Docker's accepts, but a lost table would leave them open until the watchdog reloads it). The default mark is `0x44524a4b`, the default NFLOG group of the drop log is `5`; these must match among the portal, the nft template and the drop-log listener.

### 5. Security invariants
These are properties of the system that the code and the tests must protect. The detailed mutation matrix is in the [3.5 Propagation matrix](#propagacios-matrix) section.

#### 5.1. Access
1. **Everything blocked by default.** Both the forward and input chains have `policy drop`.
2. **Password is not enough.** After a successful password (and TOTP) login, a separate rule selection and `POST /api/access` are required.
3. **Every authorization is bound to an IP and a TTL.** The kernel timeout expires even if the portal is not running.
4. **MAC binding on the LAN.** If the MAC cannot be resolved from ARP, access is denied; even with a faulty `client_mac` list, authorization without a MAC is not possible.
5. **Host SSH only with an explicit rule.** Only an input rule that explicitly lists 22 can open TCP 22; a full-access rule never opens SSH.
6. **The portal port (8100) is reserved.** Validation of host rules does not allow adding it; the portal's own, earlier-running accept rule handles it.
7. **The block precedes everything.** The block chain runs before grants and pre-auth, so no active connection can bypass it; removing the block does not require re-authorization. Toward the host it applies only to traffic from the LAN interface: block entries restrict the LAN clients, not inbound WAN traffic to the host.
8. **fail2ban overrides everything.** Packets from a banned source are dropped in both the forward and input chains; only the portal and DHCP remain reachable.
9. **Pre-auth is intentionally public.** Every client can reach the pre-auth destinations without logging in; the list must be kept minimal. The `input`-direction pre-auth rule opens the specified ports of the portal machine **before** login, thereby bypassing the portal gate: it may only be used in justified cases, for the most necessary ports. It never opens 22, 53, 67, 2019 or the portal port. Its `scope` is `lan` by default (from `HV_LAN_IF`, or `HV_WAN_IF` in single-NIC mode); only an explicit `any` opens the port from the WAN. `block` and fail2ban override this too.
10. **Breakglass is emergency-only.** The chain is not flushed on reload; the rule must be deleted immediately after use.
11. **IPv6 is always dropped, in every case.** The raw prerouting `loopback_guard`, the forward chain (first rule) and the input chain (right after the loopback accept, before `breakglass`) drop every IPv6 packet; no rule accepts IPv6, and the boot table drops it too. Only loopback (`::1` on `lo`, which cannot come from the network) passes. `docker/setup-host.sh` and `install.sh` always set `net.ipv6.conf.<HV_LAN_IF>.disable_ipv6 = 1` in `/etc/sysctl.d/90-dropjak.conf` in two-NIC mode; single-NIC mode has no separate LAN interface, so that line is omitted (the firewall still drops IPv6). **Requirement (two-NIC):** the client LAN must have no other IPv6 router. The firewall cannot see traffic that never reaches the gateway: a router advertisement from another device would give the clients an IPv6 path around it. Use RA guard on the switch where the LAN is shared.
12. **A private proxy entry is bound to the portal session, not only to the IP.** `/api/proxy/auth` lets a private entry (and a private domain-mode tunnel service) through only when the IP has a live session that selected the entry *and* the browser sends a `__Host-dropjak_bind` cookie naming that session (HMAC, host-bound). The cookie is set only by the two-hop bind flow (`/api/proxy/bind` on the portal, `/__dropjak/bind` on the entry) and Caddy strips it before the upstream. A second browser behind the same NAT cannot open the entry without its own login.

#### 5.2. Revocation and consistency
1. **Revocation is durable.** In case of a failed `nft` call, a pending-revocation entry remains, which is retried with backoff; partial revocation deletes only what is no longer needed.
2. **No orphaned grants at startup.** With `HV_FLUSH_ON_START=1` the dynamic sets are flushed; if flush is disabled, the portal reconciles to the empty session table, except for the explicitly insecure `HV_ALLOW_STALE_GRANTS_ON_START=1` case.
3. **`host_service_*` is not flushed.** These are the safety nets for established host connections.
4. **Locking and revocation happen under one lock.** `logout`, `terminate`, `revoke_user`, `revoke_rule`, expiry reaper: removing the session and the firewall revocation run in the same `SessionManager._lock`, so that a concurrent authorization does not lose its fresh grant.
5. **With multiple selection, per-direction union.** `full` absorbs TCP/UDP/ICMP in the same direction; an overlapping port enters the set only once.
6. **Partial revocation is precise.** The departing elements are subtracted; `_subtract_grants` skips the departing `full` if an active `full` in the same direction covers it, and returns the non-full departing parts for precise deletion.
7. **An expired session cannot be re-authorized.** During partial revocation the expired session is completely removed.
8. **Conntrack flush is limited.** `CONNTRACK_REMOVED_LIMIT = 16`: if more targeted deletions would be needed and a grant still remains, the system skips the cleanup rather than flushing at the IP level.
9. **On error, fail-closed.** Any firewall error leads to dropping the session and revoking the old union; HTTP 503.
10. **Every selected rule ID is resolved before authorization.** Thus a failed lookup does not leave a partial grant.
11. **A table resync ends the sessions.** When the `inet hatarvedelem` table was reloaded or flushed, the kernel elements of every session are gone. After a successful resync (`firewall_resync`, with `sessions_revoked`) every authorized session ends with reason `firewall_reset` (a `session_ended` audit per session, conntrack flushed); the clients see the reason and log in again. Grants are refused until the resync, so no session is authorized against the bare table.

#### 5.3. Admin and auth
- Admin endpoints are protected by `_admin_guard`; POST requests are JSON-only and same-origin checked.
- The server takes the client IP from the socket peer. The only exception is Caddy: from a loopback peer the last `X-Forwarded-For` element is used. The loopback peer must also send `HV_PROXY_KEY` (`X-Dropjak-Proxy-Key`, or `?key=` for `get_certificate`/`ask`). The key is mandatory with `HV_PROXY=1`: the Docker entrypoint refuses to start without at least 32 characters (the native install has no proxy). fail2ban therefore has no loopback exemption list any more: Caddy's requests are counted against the real client IP. Only `127.0.0.1` itself stays unbannable (`fail2ban.normalize_ip`; the input chain accepts loopback first, so such a ban could not take effect).
- `HV_WAN_HTTPS_ONLY=1`: `/api/login*`, `/api/password` and `/api/admin/*` answer `403 {"code": "https_required"}` to a source outside `HV_LAN_NET` that did not come through Caddy. LAN clients and loopback-direct callers (healthcheck, CLI) are unaffected. Each refusal is audited as `https_required`, at most once per source IP per minute. The UI shows a translated "sign in over HTTPS" message.
- The session cookie gets `Secure` with `HV_COOKIE_SECURE=1`, and on every response that goes out through Caddy even with `HV_COOKIE_SECURE=0`: Caddy serves the portal only in its `https://` site (its `http://` site only asks `/api/proxy/redirect` for a 3xx). Without a key only a proxy root domain counted. Plain-HTTP LAN logins keep working. Whenever the cookie is `Secure`, its name is `__Host-hv_session` (`Path=/`, no `Domain`, so a sibling host cannot toss one in); on plain HTTP it stays `hv_session`. The server reads both names (the `__Host-` one wins) and logout expires both.
- The HTML pages' CSP has no `'unsafe-inline'` in `script-src`: the inline scripts of `index.html` and of the proxy challenge page are allowed by their SHA-256 (`inline_script_hashes`, computed from the file as served), and the UI uses no inline event handlers.
- `/api/*` answers only under an IP literal, the `HV_PORTAL_URL` host, `HV_PORTAL_HOSTS`, or (through Caddy) a root domain or the portal's own address; anything else is 421 (DNS rebinding).
- Export, import and factory reset require the admin's password again (and the TOTP code when enrolled); a failure counts like a failed login.
- Failed logins are also counted per login name across all WAN source IPs (`HV_ACCOUNT_LOCK_*`); LAN clients are never locked.
- Protection of the last active admin: the last admin cannot be deleted/disabled.
- Deleting a user also removes group membership.
- The admin user update restores the previous password hash if the subsequent metadata or membership write fails.
- TOTP tickets are in-memory, live for 300 seconds, are bound to an IP, single-use, and allow at most 5 attempts. Each code check reserves an attempt first (`LoginTicketStore.reserve`), so parallel requests cannot test more codes than the cap.
- The account-request approval list warns (and asks again on approve) when a pending name equals an admin's name after removing `.`, `_`, `-` and folding case.
- The audit log redacts password, hash, secret, TOTP code, recovery code, cookie, token, ticket and `otpauth://` URI; email addresses are not logged.

#### 5.4. Known limitations
These are not open bugs, but deliberately documented residual risks:

| Limitation | Impact |
|---|---|
| The `SessionManager` uses a global lock | Under high load, session operations are serialized. |
| During shutdown, revocation may be partial | The remaining elements may live until their kernel TTL; `host_service_*` and the boot guard reduce exposure. |
| `mixed` direction is only a display/audit value | The actual operations work with separate `Ports` parts per direction. |
| TOCTOU between MAC resolution and the grant | Theoretical race; MAC binding is not authentication. |
| Test environment fallbacks | Some tests use a mocked nft; real kernel behavior requires a separate live test. |
| Runtime assumptions | nft/conntrack/NFLOG behavior is modeled by the documentation and tests, but not verified in every live combination. |
| Another IPv6 router on the client LAN | The gateway drops all IPv6 it sees, but a foreign router advertisement gives clients an IPv6 path that never reaches it. Deployment requirement: no other IPv6 router on the LAN (RA guard on a shared switch). |
| Docker without `DOCKER-USER` | With Docker's nftables backend no guard can be installed; the portal runs and logs an `ERROR` every minute. |

### 6. Data model
#### 6.1. State files
In the Docker installation, the `dropjak-state` volume appears at `/var/lib/hatarvedelem`. In the native installation the same is the `StateDirectory`.

| File | Content | Format / mode |
|---|---|---|
| `users.json` | Users, role, password record, TOTP state, rule assignment. | JSON, `0600`, atomic write. |
| `groups.json` | Groups, members, rule assignment. | JSON, `0600`. |
| `rules.json` | Individual rules and collection rules. | JSON, `0600`; faulty entries are logged and skipped on load. |
| `firewall-settings.json` | `site_name`, `motd_text`, `motd_expires_at`, `registration_enabled`, `preauth`, `block`. | JSON, `0600`; atomic replacement after validation. |
| `fail2ban.json` | Active bans, counters, configuration. | JSON, `0600`; restored on startup. |
| `audit.jsonl` | Security audit log, new line = one JSON object. | JSONL, `0600`, fsync; size-based rotation. |
| `drops.jsonl` | NFLOG drop records. | JSONL, rotation 10 MiB / 5 files. |
| `rules.json.admin-full-backup-<timestamp>` | Safety backup made when removing an old reserved identifier. | `0600`, only during migration. |

Sessions are **not** persisted: the `SessionManager` is in-memory. Therefore after every container restart you must log in and authorize again.

#### 6.2. User
The main fields of the user record (the full internal schema is in `server.py`):

| Field | Meaning |
|---|---|
| `user` / name | Unique login name. |
| `role` | `admin` or `user`. |
| `enabled` | A disabled user cannot log in. |
| `pending` | Came from a public account request, not yet approved. Missing value `false`; faulty value `true` (fail-closed). |
| `email` | Contact address from the account request; not an authentication factor, not logged. |
| `rules` | Directly assigned rule IDs. |
| `groups` | Group memberships. |
| `totp_required` | Whether 2FA is mandatory. |
| `must_change_password` | Password change mandatory at first login. |
| password record | PBKDF2-HMAC-SHA256, per-user salt, iteration count, hash; never plaintext. |
| TOTP fields | Secret, last used step, recovery-code hashes. |

The password is not a simple hash: the system uses a PBKDF2-HMAC-SHA256 record, and the default of `HV_PBKDF2_ITERATIONS` is `600000`.

#### 6.3. Rule
Stored fields of an individual rule:

```json
{
  "label": "Web only",
  "description": "",
  "tcp": [80, 443],
  "udp": [443],
  "icmp": false,
  "full": false,
  "direction": "forward",
  "default_ttl": 3600,
  "max_ttl": 86400,
  "created": 1792500000
}
```

- A missing `direction` value on load becomes `forward`.
- A `full` rule allows every port and protocol in its own direction; in the forward direction this means the internet, in the host direction validation forbids it.
- The host (`input`) rule accepts only explicit TCP/UDP ports; `full`, ICMP and the old service list are not permitted.
- The port field accepts a port, a `lo-hi` range and their comma/space-separated list (`22, 80, 8000-8100`). Storage is backward compatible: simple ports are integers, ranges are `"8000-8100"` strings; on load we internally split them into ports and merge overlapping ranges.
- 8100 is reserved, including within a range; 22 can be opened only in a separate, explicit host rule.

Stored fields of a collection rule:

```json
{
  "label": "Web + DNS",
  "description": "Two individual rules together",
  "members": ["web-only", "dns-only"],
  "default_ttl": 3600,
  "max_ttl": 86400,
  "created": 1792500000
}
```

A collection has no own `tcp`, `udp`, `icmp`, `full` or `direction` field: the ports and the direction are values calculated from the members. This prevents a later modification of a member from leaving a stale union behind. Collection is one level, with 1–64 members; a collection cannot contain a collection, itself, the reserved `admin-full` identifier or a full-access member.

Stored fields of a service rule:

```json
{
  "label": "Home NAS",
  "description": "",
  "service_refs": ["home/nas"],
  "default_ttl": 3600,
  "max_ttl": 86400,
  "created": 1792500000
}
```

- `service_refs` is 1–64 references of the form `<agent_id>/<service_id>`. On save the system checks that the referenced service exists and is enabled; on load a missing or disabled reference does not discard the rule but yields empty resolved ports (fail-closed), so the error does not fall silently into the grant.
- The service rule's ports are calculated not from the rule but from the referenced tunnel mappings (`service_tcp`/`service_udp` in the in-memory `Rule`, only the reference is on disk). When any effective field of the mapping (`proto`, listening port, target host, target port, domain) is modified, the rule's resolved ports and its non-persisted mapping signature are refreshed, and the affected sessions are revoked.
- **A domain-mode service can also be selected as `service_refs`.** In this case the rule does not open a firewall port but authorizes the service's domain through the proxy gate (`service_domains` in the resolved `Rule`, `session_domains` in the session). The domain name is part of the mapping signature and is also watched by the editor's change detection, so renaming invalidates the previous decision and revokes the sessions even while the internal listen port is left unchanged, and disabling fails closed and does not provide a domain. A mixed rule (containing both port and domain services) still grants the ports as forward grants, alongside the domain.
- The service rule cannot be combined with the `tcp`, `udp`, `icmp`, `full`, `members` or `domains` fields, and can only be of `forward` direction. It can be a collection member; the collection's union also includes the service's ports (and the domain of a domain-mode member, without ports).
- The referenced service or agent cannot be deleted while a rule references it; the operation is rejected with the list of referring rules. Disabling, by contrast, is always allowed: access ceases in a fail-closed manner, and the sessions of the referring rules are revoked.

#### 6.4. Group
The group is the intermediary between users and rules. A user's effective rules are the union of the direct `rules` and the rules inherited through groups. Group membership is also removed when the user is deleted. The detailed group schema works according to `server.py` and the relevant tests; the full list of field names is not included here because the document does not want to invent internal implementation details.

#### 6.5. Settings
The validated fields of `firewall-settings.json`:

| Field | Type | Default | Note |
|---|---|---|---|
| `site_name` | string, max 64 | empty → `Dropjak` | Portal header, browser title, issuer for new TOTP enrollment. |
| `motd_text` | string, max 2000 | empty = disabled | Post-login notice; only the authorized portal receives it, and only while it is valid. |
| `motd_expires_at` | ISO-8601 UTC string | empty = permanent | End of the notice's validity; after the expiry time the server does not send it. |
| `registration_enabled` | boolean | `false` | Public account request switch. |
| `preauth` | list | empty | Pre-login destinations/ports; the entry's `direction` field is `forward` (default) or `input`. Missing field on load is `forward`; fail-closed fallback on error. An `input` entry has a `scope` field, `lan` (default; a stored entry without it loads as `lan`) or `any`; it is part of the export/import and is set with the **Scope** select of the pre-auth form. |
| `block` | list | empty | Always-blocked destinations/ports; on error the last good state remains. |

The limits of `settings_store.py`: at most 64 entries, 64 ports, a 64-character label, a 64-character site name, a 2000-character notice; rule identifiers have a strict regex. `motd_expires_at` also includes a time zone and is stored in canonical `YYYY-MM-DDTHH:MM:SSZ` form.

A pre-auth or block destination with host bits (`10.0.0.5/8`) is rejected when saved through the UI/API or imported ("host bits must be zero"). Loading a stored, hand-edited file is lenient: the destination is normalized to its network (`10.0.0.0/8`) with a `[settings] WARNING` log line, instead of invalidating the whole file. `Firewall._custom_dst` stays strict, so a host-bit network never reaches the kernel.

#### 6.6. Audit and drop log
The common fields of an audit entry: `ts`, `time`, `event`, `severity`, `ip`, `user`, `ua`. The value of `severity` is `info`, `warn` or `alert`; old entries count as `info`. The event families: authentication, access, session, admin, fail2ban, service/firewall, CLI, TOTP-ticket lifecycle.

The drop log comes from NFLOG group 5 and stores only the packet header, not the payload. Drops caused by `fail2ban` are merged by the portal into a single ban event, so the UI shows the ban and the "post-fail2ban attempt" summary in one row.

### 7. Portal UI
The portal is a single `index.html` with embedded CSS and JavaScript. Three languages: Hungarian (`hu`, default), English (`en`), German (`de`). The theme follows the system setting, but can also be switched manually in the bottom-right corner; the choice is kept in `localStorage`.

#### 7.1. Client-side screens
| Screen | Function |
|---|---|
| Login | Username, password, captcha (local proof-of-work or Cloudflare Turnstile). |
| TOTP | 6-digit code or recovery code; tied to a ticket, IP-checked. |
| TOTP enrollment | Browser-generated QR (Nayuki qrcodegen inline), base32 secret and `otpauth://` URI with a manual fallback. |
| Recovery codes | After the first successful enrollment, shows the 10 codes once. |
| Ban | During an active fail2ban ban, a ban screen with a countdown instead of the login. |
| Notice (MOTD) | A modal with its own styling, shown once after login and before access selection; it stays over the screen until the Close button. |
| Rule selection | Multiple cards can be selected; the TTL is in whole hours, with the strictest `max_ttl` as the upper limit. **Select all** selects up to the server's 16-rule limit; **Max** enters the largest whole-hour value of the selection. |
| Session | Active accesses, expiry, modification, logout. |
| Password change | Separate endpoint; requires a valid session. |

#### 7.2. Multiple selection and live update
In 3.2.0, the authorized portal polls `/api/status` every 30 seconds and refreshes the rule catalog. The modification screen does not log the user out: still-valid selections remain, a selection revoked by the server disappears, and the UI indicates that the affected access must be re-authorized. The TTL hint lists every selected rule, marks the rule that provides the upper limit, and shows the full list in the tooltip.

In the rule list header, the **Select all** button selects every available rule up to the server's `limits.max_rules` limit (in its absence, up to 16); the order of existing selections is preserved, and pressing the button again does not change anything. The **Max** button next to the TTL field enters the largest whole-hour value of the selection: `floor(min(limits.max_ttl, max_ttl of the selected rules) / 3600)`, not going below the field's minimum. Without a selection, the global `limits.max_ttl` is the basis. The value entered this way is exactly what the submission accepts as whole hours (the `maxSec` upper limit is checked by both the client and the server); for a rule shorter than one hour, the field remains disabled.

#### 7.3. Admin interface
The tabs of the admin page:

| Tab | Function |
|---|---|
| Users | Creating, editing and deleting users, role, rules, groups, TOTP reset, approving/rejecting pending account requests. Last-admin protection. A read-only **Preview** in the rows. |
| Groups | Groups and memberships, rule assignment. |
| Rules | Individual rules, collection rules, service rules, duplication, password generator, direction (`Direction`), TTLs, ports. `Domain (proxy)` and `Service` are separate checkboxes, not direction values. On the rule form, the `Users` and `Groups` selectors provide direct assignment for every rule type. |
| Proxy and tunnels | Direct TCP/UDP port proxies (nftables DNAT, without an agent), as well as WireGuard-based tunnel agents and their services for their own network, on one page, in a separate tunnel block. Within the agent card, the service editor provides dynamic mapping rows (protocol, external port, internal port, add/delete), as well as a `Domain (optional)` field and a `Public` checkbox. When a domain is filled in, a single `Target port` field appears instead of the mapping rows; the table shows the hostname, the `public` marker and the target port for a domain service. The active state is handled exclusively by the switch in the service's row (there is no separate "active" tick on the form); a new service is always created as active. The **Test** button in the service row checks the complete access path and displays the result within the row. |
| Sessions | Active sessions, forced termination, selected rules. |
| Firewall | Per-IP overview, kernel grants, sessions; Raw rules view (`iptables -L -n` style), with the pre-auth/block chains. |
| Drop log | Drops by source/destination, protocol/port/text filters, chart, fail2ban events merged. |
| Fail2ban | Status, active bans with countdown, waiting attempts, manual ban/unban, login and drop thresholds, separate drop-metric switches. |
| Logs | Audit log filters: event, user, text, severity, count. Event selector from known codes. The `before` cursor is available only at the API level. |
| Settings | Firewall name, post-login notice (MOTD), account requests, pre-auth (with forward/input direction), block; validation, nft application, atomic save. At the bottom, the **Save and restore configuration** section: export, import and factory reset. |

On the **Rules** tab the password generator is client-side; **Duplicate** calls the `action: "duplicate"` API. Changes on **Settings** first go to nftables and are written to the file only on success; on error the previous chains are restored. The exception is the `site_name` and `motd` operation: these are display-only data, so they are written directly, without touching nft.

The service editor opens within the agent card on the **Proxy and tunnels** tab. The mapping rows contain the protocol (`tcp`, `udp`, `both`), the external (`listen`) and internal (`target`) port; the target host is common at the service level. Both the external and internal fields accept a list or a range (`80,443`, `8000-8100`), and the client checks before saving that the number of items on the two sides matches. The old separate "tunnel port" field is gone: in port mode the internal tunnel port always matches the external port, so the row does not include a separate tunnel port. Filling in the **Domain (optional)** field switches the service into domain mode: the mapping rows are hidden and a single **Target port** field remains (the target host is still common); the internal tunnel port is allocated by the server. The **Public** checkbox means, in port mode, access without portal login, and in domain mode, access without a domain rule; a private domain service requires a domain rule. There is no separate "active" checkbox on the form: the state is handled by the switch in the service row, and a new service is always created as active. For a domain service, the row's switch does not send a `domain_target` field, so the client sends the existing mapping; previously an empty target port would be saved in this case, and saving failed with the "at least one port is required" error. On the service rule form, the `Service` checkbox opens the reference selector, which also offers domain-mode services (marked ` · Domain`); these provide their domain through the proxy gate instead of ports (the help text says so too), and the rule card shows the form `Service: <label> (<domain>)`. The `Domain (proxy)` rule selector still lists the hostnames of domain tunnel services (marked ` · Tunnel`) — the server's `_domain_names` set accepts the same names; on the rule cards and in the session view the service name appears as a label (`Service: …`). The UI includes the new labels, error messages and help texts in all three languages (hu/en/de).

The tunnel section is a separate, distinct block within the **Proxy and tunnels** tab: at the top of the agent list, the **Refresh status** button (visible even with an empty list) issues only a read-only `GET /api/admin/tunnels/status` request, and from the response replaces only the tunnel view; next to it the `Checked: HH:MM:SS` time appears, and during loading the button is disabled and shows a spinning indicator. On error, the message also appears at the top of the agent list (a copy of the flash at the top of the page), so a rejected deletion/rename is visible where the operation happened; there is no native `alert`/`confirm`. "New agent" is a collapsible form, with agent cards below it. The card header contains the name, the monospace address, the status indicator, the toggle switch, and, right-aligned, the Download installer, Edit and Delete actions; in a single meta row, the age of the handshake, the age of the last sync (`N s` or `no sync`), the human-readable RX/TX traffic and the service count are shown. The status indicator is **active** only if the agent is enabled, the handshake is fresher than 180 seconds and the last successful configuration sync is at most 90 seconds old; otherwise `online`/`offline`, and for a disabled agent a neutral `disabled` (not to be confused with offline). The service rows are in a column layout (Name, Target, Access, Status, Actions); the Access column shows the Portal/Public/Domain label and the list of mappings; Actions includes **Test** along with Edit and Delete. Deletion is still two-step, with in-row confirmation. Only one form can be open at a time: "New service" and the editor of an existing service use the same state, so opening one closes the other and the tab does not jump. The Test result appears below the row in a green/red badge with per-mapping details, and in a badge on API error too, not in a popup; it disappears by itself after 60 seconds (only the row's result view goes away, the panel is not re-rendered), and editing, toggling or deleting the service immediately clears the previous result. On a narrow screen the rows turn into label/value pairs and the page does not scroll horizontally; an empty agent and service list gets a separate message. The tunnel block is visually distinct from the WireGuard settings and the direct port proxies, but those remain unchanged.

The **Domains** tab also shows a **Tunnel domains** section below the proxy entries, about the domain tunnel services (full hostname, agent/service, target, visibility). The hostname, target port and visibility must still be edited on the **Proxy and tunnels** tab; here the **Challenge** can be set per service, and the row's **Save challenge** button with the `tunnel_service_save` action writes only the `challenge` field, without touching the nft rules and the mappings. The challenge takes effect through the domain service's synthetic Caddy target (`_tunnel_domain_target`), under the same conditions as for proxy entries; for a non-domain service, saving is rejected with an error message. An empty condition list deletes the challenge.

The **Preview** button in the Users tab rows (`GET /api/admin/preview?user=<name>`) shows the selected user's portal access screen using the existing portal renderer, in read-only mode. The view contains the direct, group and collection rules, the domains, the TTL limits, as well as the TOTP and approval status. This is not real impersonation: no session is created, no nft authorization is opened, every action button and rule card is disabled, a "Preview: <user>" bar at the top indicates the mode, and opening it writes an `admin_user_preview` audit entry. The endpoint requires an admin session and a valid origin header.

#### 7.4. Entity references
On the admin pages, names referring to other entities are clickable links: the rule, group and user name switches to the corresponding tab, waits for the admin state to load, and then opens the editor for that item. With a cold cache, therefore, an empty "new" form does not open. Domain hostnames go to the Domains tab and scroll to the corresponding proxy route row, briefly highlighting it; there is no separate route editor. The rule and group columns show the name visible in the editor, or the identifier itself if the identifier is unknown. The links are focusable, can be activated with Enter, and get a readable title in all three languages.

#### 7.5. Account requests
`registration_enabled` defaults to `false`. When enabled, the **Request account** button appears on the login page. The request asks for a password, password confirmation (UI only) and an email address, with the usual captcha. The resulting account has `pending=true`, `enabled=false`, `rules=[]`, `totp_required=false`, `must_change_password=false`, role `user`; it does not receive a cookie and cannot log in. The admin approves or rejects it on the Users tab. Approval does not grant a rule and does not grant access.

Registration is JSON-only, same-origin, IPv4-only, with a dedicated rate limit (3 requests / 10 minutes / source IP). The email address is stored but is not sent out, is not verified and cannot be used for password reset.

#### 7.6. Configuration bundle (config flash)
At the bottom of the **Settings** tab, the entire configuration can be exported into a single JSON file, the same can be re-imported, and it can be reset to factory state. All three operations require an admin session and a valid `Origin` header; only the operation, the counts and the result are logged, never the bundle contents or a secret.

**Bundle format.** The file wrapper:

```json
{
  "format": "dropjak-config",
  "format_version": 1,
  "app_version": "3.24.0",
  "created_at": "2026-10-22T12:00:00Z",
  "sections": {
    "settings": {}, "rules": {}, "groups": {},
    "users": {}, "certs": {}, "fail2ban": {}
  }
}
```

`format` and `format_version` are mandatory; the server rejects an unknown major version, a missing or unknown section, and never silently omits a section. All six keys of `sections` are mandatory:

- `settings`: the complete, normalized content of `firewall-settings.json` (site name, MOTD, registration, proxy domains/routes, port proxies, the tunnel agents and their multi-port services, pre-auth and block).
- `rules`, `groups`: the storage form of the rule and group store (with collection members, domains).
- `users`: password hash (PBKDF2 salt, hash, iteration), role, status flags, direct rules, email, TOTP secret, TOTP step, recovery-code hashes. The admin provisioning marker (derived from the `.env` password) is **not** exported; only the private pre-import backup keeps it.
- `certs`: per root domain, the certificate chain and the private key in PEM.
- `fail2ban`: exclusively the settings with the 13 known keys.

**Excluded:** audit and drop logs, sessions, active bans and waiting attempts, `.env`, `.secret`, PID/socket/lock files, and Caddy's ACME bundles. Import does not overwrite bans; applying the `fail2ban` setting may release a ban according to the usual rules.

**Export.** `POST /api/admin/config/export`, `{"password": "...", "code": "..."}` (the admin's current password, and the TOTP code when enrolled; `code` is optional otherwise). Import and reset need the same two fields next to their own. The response is `Cache-Control: no-store`, `Content-Disposition: attachment`, filename `dropjak-config-<version>-<UTC time>.json`. The file contains password hashes, TOTP secrets, recovery-code hashes and private keys: it must be handled confidentially. A failed export gives a detailed error in the response, but only `config_export_failed` is logged.

**Import.** `POST /api/admin/config/import`, `{"bundle": {...}, "confirm": "..."}`; the request is at most 8 MiB. The server first validates the entire bundle in memory: schema and version, settings (`validate_state`), user records, rules and groups, certificate pairs (key/PEM match, coverage of the root domain, expiry; an expired pair is acceptable only for restoration), the `fail2ban` section, and referential integrity: rule domain → proxy route, user → rule, group → rule/member, certificate → root domain, collection members. The import intentionally does not require the existence of `service_refs` references, because the referenced tunnels may come in the same bundle; resolution is fail-closed at load and at authorization. At least one enabled, non-pending admin account is mandatory. For an invalid bundle the response is 400, and nothing is written.

If the current state is not empty, the client must enter the **current** site name (`confirm`); on an empty installation this can be omitted. An installation created only from `.env` with the seeded rule set counts as empty; the UI is more cautious and asks for confirmation even with a single user. For a valid bundle, the server, before the first write, saves the current state as `config-backup-<UTC>.json` with `0600` in the state directory, then overwrites the sections through the existing storage paths, applies the nftables rules and the fail2ban setting, and finally closes every session and login ticket. It then restarts with `SIGTERM`; Compose's `restart: unless-stopped` starts it again. On an error during the write, it restores the previous state from the backup, does not restart, and writes a `config_import_failed` / `rollback_failed` entry. The backup itself is an importable bundle, so it can be restored manually if necessary.

**`.env` admin and the provisioning marker.** On startup `provision_admin` re-validates the `HV_ADMIN_USER`/`HV_ADMIN_PASSWORD` pair against the stored marker. An imported user record without a marker keeps this installation's marker for the same user name; for `HV_ADMIN_USER` without one, a fresh marker of the current `.env` password is stored (`server._carry_provision_marker`). So after the restart `provision_admin` sees the `.env` password as already provisioned, and the imported (possibly UI-changed) password stays in effect. A bundle from an older version that still carries a marker imports it unchanged; if that marker does not match the `.env` password, the `.env` password becomes valid after the restart, with a mandatory change at first login.

**Factory reset.** `POST /api/admin/config/reset`, `{"confirm": "<site name>"}`; confirmation is always mandatory, and without a site name the word "Dropjak". First the runtime state is cleared (sessions and tickets, releasing every fail2ban ban, nftables flush and flushing the custom chains); if this fails, the operation stops with 503 and nothing is deleted. Then users, rules, groups, settings, fail2ban state and certificates are deleted, along with the previous `config-backup-*.json` backups. The logs, `.env`, service files and application assets are untouched. The `config_reset` audit entry is written after the deletion, then the service restarts; the `.env` admin is recreated at that point. If there is no `.env` admin, recovery is possible only from the command line; the UI warns about this.

### 8. API surfaces
The list below comes from the `server.py` dispatch table. POST endpoints expect a JSON body; the server checks `Content-Type` and the `Origin` header where relevant. Errors are typically of the form `{"ok": false, "error": "...", "code": "..."}`.

#### 8.1. Public and session endpoints
| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `/api/challenge` | Proof-of-work captcha challenge. | no |
| GET | `/api/status` | Version, `registration_enabled`, session status, rules, grants; for an authorized session, the still-valid `motd`. | no / according to cookie |
| POST | `/api/register` | Public account request; pending account. | no |
| POST | `/api/login` | Password login, captcha; ticket in the case of TOTP. | no |
| POST | `/api/login/totp` | TOTP code verification, session creation. | ticket |
| POST | `/api/login/totp/enroll` | Enrollment confirmation, recovery codes. | ticket |
| POST | `/api/login/recovery` | Use a recovery code. | ticket |
| POST | `/api/access` | Authorize rule(s) and TTL; multiple payload: `{"rules": [...], "rule": first, "ttl": N}`. | session |
| POST | `/api/logout` | Logout, revoke the grant. | session |
| POST | `/api/password` | Password change. | session |

The `/api/status` response for an authorized session also contains the `selected_rules`, `selected_rule_labels` and per-direction `grants` fields; the old `rule`, `rule_label`, `grant` fields remain for compatibility. `MAX_SESSION_RULES = 16`. For client-side display of the rules, the response also provides a `services: [{ref, label, tcp, udp, domain}]` list for the selected service rules (the session payload also contains a `service_refs` field); for a domain-mode service, `domain` is the hostname, the ports are empty, and `ports_label` has the form "Service: <label> (<domain>)". The access card displays the reference on `ports_label` in the form "Service: …".

#### 8.2. Admin GET endpoints
| Path | Content |
|---|---|
| `/api/admin/state` | Full admin state: users, groups, rules, settings, version. |
| `/api/admin/preview?user=<name>` | A user's portal access view in read-only preview; it does not open a session or nft authorization, and writes an `admin_user_preview` audit entry. |
| `/api/admin/logs` | Audit log; `limit`, `event`, `events`, `user`, `q`, `before`, `severity`, `ip`. |
| `/api/admin/sessions` | Active sessions. |
| `/api/admin/firewall` | Per-IP kernel grants and sessions. |
| `/api/admin/firewall-rules` | Raw nft rule list. |
| `/api/admin/drops` | Drop log, with filters. |
| `/api/admin/settings` | Pre-auth/block/site settings. |
| `/api/admin/fail2ban` | fail2ban status, bans, waiting attempts. |
| `/api/admin/tunnels/status` | Read-only tunnel status: `{ok, checked_at, tunnels}`; the shape of `tunnels` is the same as in the admin state, with `last_sync` in seconds per agent. It does not write settings and does not touch nftables. |
| `/api/admin/config/export` | POST with the admin's password (and TOTP code): download of the complete configuration bundle (`no-store`, `attachment`). |

#### 8.3. Admin POST endpoints
| Path | Operations |
|---|---|
| `/api/admin/users` | create, update, delete, approve, reject, totp reset, role/membership management. |
| `/api/admin/groups` | create, update, delete, member assignment. |
| `/api/admin/rules` | create, update, delete, duplicate; individual, collection and service rule (`service_refs`). The optional `users` and `groups` fields of create/update set the direct assignment of the rule (atomic rewrite of `users.rules` / `groups.rules`, audited addition/removal). |
| `/api/admin/sessions` | terminate. |
| `/api/admin/settings` | pre-auth/block modification, `site_name`, `registration_enabled`, `motd` (notice text and expiry), the `proxy` and `port_proxies` operations, and the tunnel operations (`tunnel_settings`, `tunnel_agent_add`, `tunnel_agent_update`, `tunnel_agent_delete`, `tunnel_service_save`, `tunnel_service_delete`, `tunnel_service_test`). `tunnel_service_test` only reads, does not write settings. |
| `/api/admin/fail2ban` | configure, ban, unban, unban-all. |
| `/api/admin/config/import` | Validation, saving and loading of the complete configuration bundle; typed site name when the state is not empty. |
| `/api/admin/config/reset` | Factory reset with typed site name; runtime firewall/fail2ban cleanup, deletion, restart. |

Admin operations are logged (`admin_*` events), a denied request as `admin_denied` / `admin_request_rejected`, and an execution error as `admin_action_failed`.

#### 8.4. Static resources
| Path | Content |
|---|---|
| `/` | `index.html`. |
| `/icon.png`, `/favicon.ico` | Icon. |
| `/blocked.png` | Image of the ban screen. |

#### 8.5. Proxy bind hops (private entries)
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/proxy/bind?host=<entry>&r=<uri>` | Portal hop, only through Caddy on the portal's own address or root domain. It needs the portal session cookie of a session that selected the private entry from this IP, then answers `302 https://<entry>/__dropjak/bind?t=<ticket>&r=<uri>`. The ticket is single-use, lives 60 s and is bound to the session id, host and IP. Otherwise `302 /` (the portal page) and a `proxy_bind_denied` audit. |
| GET | `https://<entry>/__dropjak/bind?t=&r=` | Entry hop, answered by `/api/proxy/auth` (forward_auth): spends the ticket and answers `302 https://<entry><r>` with `Set-Cookie: __Host-dropjak_bind=…; Secure; HttpOnly; SameSite=Lax; Path=/` (`proxy_bind_completed`). A bad ticket gets the 401 login page (`proxy_bind_failed`, not counted by fail2ban). |

Without a valid bind cookie, a page load of a private entry from an IP that holds a matching session gets `302` to the portal hop, any other request `401 {"code": "proxy_bind_required"}`; neither counts for fail2ban or the drop log. `r` must be an origin-relative path (no `//`, backslash or space). The bind cookie is valid as long as the session (checked on every request) and at most `HV_MAX_TTL`; the key is new per process, so after a restart the browser repeats the hop on the next page load.

The portal's `server_version` value is `Dropjak/2`; this is not the same as the product version. The product version is given by the `VERSION` file and the `version` field of `/api/status`.

### 9. Configuration
#### 9.1. Installation modes and mandatory environment variables
`HV_SINGLE_NIC` selects the mode (default `0`):

- **`0` — two-NIC gateway (default).** The host has a separate client LAN interface. `HV_LAN_IF`, `HV_WAN_IF` and `HV_LAN_NET` are required and the LAN-scoped features are active.
- **`1` — single-NIC host.** One interface (`HV_WAN_IF`) faces the internet and the clients; the portal is reached by source-IP matching (`HV_PORTAL_NET`). `HV_LAN_IF`/`HV_LAN_NET` are not required and are ignored (a startup log line notes if they are set). Useful for a VPS with a single public NIC, where the VPN/other services and the portal clients come from the internet.

The Docker entrypoint considers these mandatory; without them the container does not start (fail-closed):

| Variable | Example | Meaning |
|---|---|---|
| `HV_WAN_IF` | `eth0` | Interface toward the internet; in single-NIC mode also the client-facing interface. Required in both modes. |
| `HV_LAN_IF` | `eth1` | Client-side interface. Two-NIC mode only. |
| `HV_LAN_NET` | `192.168.10.0/24` | Client network in IPv4 CIDR. Two-NIC mode only. |
| `HV_PORTAL_NET` | `0.0.0.0/0` | From where the portal is reachable; when unset or empty, `0.0.0.0/0` (public). In single-NIC mode this is the only way to restrict portal access. |

In two-NIC mode `HV_LAN_IF` and `HV_WAN_IF` cannot be the same. The portal is always reachable from the LAN; by default it is public toward the WAN too. Set `HV_PORTAL_NET` to a management CIDR when the portal should not be reachable from the internet.

**What single-NIC mode omits.** The template marks every LAN-only line with `__LANONLY__`; the renderer replaces the marker with nothing in two-NIC mode and with `# ` in single-NIC mode. The omitted rules are: DHCP (UDP 67/68), LAN DNS, the HTTP captive redirect (`redirect to :PORT`), masquerade, the LAN MAC-binding drops and ARP-based `client_mac` binding, the LAN spoof checks, the WAN→LAN guard, the container-pivot-to-LAN rule, the LAN input-block jump and the LAN portal accept. Everything else stays active: grants (`allowed_v4`, `allowed_tcp`/`udp`/`icmp`), fail2ban, `no_forward_v4`, the container guards, the IPv6 drop, `breakglass`, pre-auth, the tunnel chain, port proxies, the proxy 80/443 accepts, the source-based portal accept (`ip saddr HV_PORTAL_NET tcp dport PORT accept`) and the host input accepts.

**Security trade-off.** In single-NIC mode grants are IP-based only: `MAC_BINDING`/`Firewall.mac_binding` is `False` even if stale LAN values remain, so a `client_mac` set element and ARP lookup are never required. On a public interface an IP can change hands (DHCP, NAT, a reassigned address), so an active grant may briefly apply to another host at the same address; the TTL limits the window. The admin `block` chain stays forward-only, because its input jump is LAN-scoped and is omitted — block entries cannot cut WAN input traffic in this mode. Because the portal is on the public interface and the direct portal speaks plain HTTP, serve it through the HTTPS proxy (`HV_PROXY=1`, Caddy) or set `HV_WAN_HTTPS_ONLY=1` before exposing it; the startup warning repeats this.

#### 9.2. Main settings
| Variable | Default | Role |
|---|---|---|
| `HV_SINGLE_NIC` | `0` | `1`: single-NIC host (see 9.1). |
| `PORT` | `8100` | Portal port on the host. |
| `HV_PORTAL_URL` | empty | Canonical portal address. |
| `HV_SESSION_TTL` | `3600` | Default access time in seconds. |
| `HV_MIN_TTL` / `HV_MAX_TTL` | `60` / `2592000` | Global TTL limit; the rule's `max_ttl` narrows it further. |
| `HV_AUTH_TTL` | `600` | Between password login and rule selection; clamped to 60–3600. |
| `HV_POW_DIFFICULTY` | `4` | Proof-of-work difficulty (1–6 leading hex zeros). |
| `HV_CHALLENGE_TTL` | `600` | Captcha challenge lifetime. |
| `HV_PBKDF2_ITERATIONS` | `600000` | Password hash iteration count. |
| `HV_RATE_WINDOW` / `HV_RATE_MAX` | `60` / `10` | Login rate limit. |
| `HV_TOTP_ISSUER` | `Dropjak` | TOTP issuer fallback when there is no site name. |
| `HV_COOKIE_SECURE` | `0` | `1`: `Secure` session cookie on every response (plain-HTTP LAN logins then stop working). Responses through Caddy get `Secure` anyway. |
| `HV_PROXY` / `HV_PROXY_KEY` | `0` / empty | Caddy domain proxy; with `HV_PROXY=1` the key (at least 32 characters, `openssl rand -hex 32`) is mandatory, given to both services. |
| `HV_PROXY_DOMAINS` / `HV_PORTAL_DOMAIN` | empty | First-start seed for Admin → Settings → Proxy: comma-separated root domain(s) and the Dropjak subdomain (strictly under a root). Applied only while the settings file does not exist; afterwards the admin UI is authoritative. `configure.sh` fills them in HTTPS mode. |
| `HV_WAN_HTTPS_ONLY` | `0` | `1`: login, password and admin endpoints answer `403 https_required` to non-LAN sources that did not come through Caddy. Needs `HV_PROXY=1` for WAN logins. |

#### 9.3. Firewall, state, fail2ban
| Variable | Default | Role |
|---|---|---|
| `HV_FWD_MARK` | `0x44524a4b` | Forward mark; the Docker guard aligns with it. |
| `HV_DROP_LOG_GROUP` | `5` | NFLOG group. |
| `HV_NFT_TABLE` / `HV_NFT_SET` | `hatarvedelem` / `allowed_v4` | nft table and full-access set. |
| `HV_FLUSH_ON_START` | `1` | Dynamic set flush at startup. |
| `HV_ALLOW_STALE_GRANTS_ON_START` | `0` | With `1`, old grants may remain alive without a session; **not secure**. |
| `HV_FIREWALL_WATCHDOG` | `1` | Firewall watchdog. |
| `HV_DRY_RUN` / `HV_SKIP_FIREWALL` / `HV_RUN_AS_ROOT` | `0` | Does not write nft / skips loading / runs as root. The latter two are **not secure**. |
| `HV_FAIL2BAN` | `1` | Switch for login-based banning (0: only login monitoring is off). |
| `HV_FAIL2BAN_MAX` | `5` | Failed logins until a ban (1–100). |
| `HV_FAIL2BAN_WINDOW` / `HV_FAIL2BAN_BAN` | `600` / `3600` | Time window and ban length. |
| `HV_FAIL2BAN_DROP` | `1` | On first start, gates both drop metrics; at runtime they can be switched separately. |
| `HV_FAIL2BAN_DROP_COUNT_ENABLED` / `HV_FAIL2BAN_DROP_PORTS_ENABLED` | `1` | First-start default for the two drop metrics. |
| `HV_FAIL2BAN_DROP_MAX` / `HV_FAIL2BAN_DROP_PORTS` | `120` / `12` | Packet and port threshold (1–10000 / 1–4096); 0 is invalid and falls back to the default. |
| `HV_FAIL2BAN_DROP_WINDOW` | `180` | Drop time window (30–86400). |
| `HV_ADMIN_ENABLED`, `HV_ADMIN_USER`, `HV_ADMIN_PASSWORD`, `HV_ADMIN_PASSWORD_FILE` | `0` / empty | Creating/updating the admin account at startup; a file can also be given. |
| `TURNSTILE_SITEKEY`, `TURNSTILE_SECRET` | empty | Optional Cloudflare Turnstile; without it, local proof-of-work. |
| `HV_CONNTRACK_BIN` | auto | Custom `conntrack` binary. |

The runtime fail2ban values can be set on the admin **Fail2ban** tab; environment variables are only the defaults for the first start. Disabling login monitoring releases only login-based automatic bans, and disabling both drop metrics together releases only drop-based automatic bans; manual bans remain.

#### 9.4. State and log paths
The default root is `HV_STATE_DIR=/var/lib/hatarvedelem`; from there `users.json`, `rules.json`, `groups.json`, `firewall-settings.json` (`HV_SETTINGS`), `audit.jsonl` (`HV_AUDIT_LOG`), `drops.jsonl` (`HV_DROP_LOG_PATH`), `fail2ban.json` (`HV_FAIL2BAN_STATE`). Rotation: audit and drop log `10 MiB`, 5 files. The service catalog is `HV_SERVICES_FILE=/opt/hatarvedelem/services.json`.

#### 9.5. nft placeholders
The template contains eight placeholders, which both the entrypoint and `install.sh` fill:

```text
__LANONLY__  __LAN_IF__  __WAN_IF__  __LAN_NET__  __PORTAL_NET__
__PORT__  __FWD_MARK__  __DROP_LOG_GROUP__
```

`__LANONLY__` is substituted first: it stands at column 0 on every LAN-only line and becomes an empty string in two-NIC mode, or `# ` in single-NIC mode (commenting the line out). The other placeholders are then filled in both modes. After rendering, no `__...__` pattern may remain in the file; `install.sh` and the native units check this.

#### 9.6. Local development rule
On the local development machine you **must never run a real firewall load** (`nft -f`, `docker compose up` with the real interfaces, `install.sh`), because the forward chain's policy drop and the rule closing host SSH can also lock out the development machine. For local work, `HV_DRY_RUN=1`, `HV_SKIP_FIREWALL=1` or unit tests/mocks can be used; checking real nft behavior is the task of the dedicated VM.

### 10. Installation and operations
#### 10.1. Docker installation
```bash
git clone git@github.com:moodpatcher/dropjak.git
cd dropjak
./configure.sh              # interfaces, networks and the first admin account -> .env (0600)
sudo ./docker/setup-host.sh
DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .
docker compose up -d
docker compose ps
docker compose logs -f dropjak
```

`configure.sh` lists the available interfaces and first asks whether this is a
single-NIC host (default: yes when there is no private IPv4 interface besides
the WAN, or only one non-loopback interface). In single-NIC mode it asks only
for the WAN (internet and client) interface and writes empty `HV_LAN_IF`/
`HV_LAN_NET` values with `HV_SINGLE_NIC=1`. Otherwise it asks which one is the
LAN (clients) and which one is the WAN (internet), then the LAN network. Both
paths continue with the portal source network, the management network (may be
empty in single-NIC mode) and the portal port. The next question is how the
portal is reached by default:

1. `http://<host-ip>:PORT` — plain HTTP on the host IP (the default; no proxy
   variables are written).
2. `https://<subdomain>` — HTTPS through the Caddy proxy. It asks for a root
   domain (e.g. `example.com`) and a Dropjak subdomain strictly under it
   (e.g. `fw.example.com`), then writes
   `HV_PROXY=1`, `COMPOSE_PROFILES=proxy`, `HV_PROXY_KEY`,
   `HV_PROXY_DOMAINS`, `HV_PORTAL_DOMAIN`, `HV_PORTAL_URL=https://<sub>`,
   `HV_PORTAL_HOSTS=<sub>` and `HV_WAN_HTTPS_ONLY=1`. A re-run keeps the
   existing `HV_PROXY_KEY`; if the old `.env` had `HV_PROXY=1`, mode 2 is the
   default. When switching back to mode 1 the proxy variables are removed.

For mode 2 the DNS must already be in place, otherwise Caddy cannot obtain a
certificate: an `A` record for the root domain **and** a wildcard
`A *.root` must point at the host's public IPv4 address. The records must be
“DNS only” (no CDN proxy, so Caddy sees the real client IP) and there must be
no `AAAA` record, because incoming IPv6 is dropped by the firewall. The same
reminder is printed while asking and in the final summary.

The `.env` values `HV_PROXY_DOMAINS`/`HV_PORTAL_DOMAIN` are only a
**first-start seed**: on startup the portal writes them into
`firewall-settings.json` if that file does not exist yet. After the first
start, Admin → Settings → Proxy is authoritative and later starts never
overwrite it, so the domains can be changed in the UI without touching `.env`.
An invalid seed (for example a subdomain outside the root) is logged as a
warning and ignored; startup continues with the defaults.

After the access-mode question the script asks for the first admin account. It
writes `.env` with mode 0600 and offers the current values as defaults when it
is re-run; the old file is backed up as `.env.bak-<timestamp>`. Leave the admin
password empty to generate a random one (it is printed and written to `.env`).
The portal is public by default (`HV_PORTAL_NET=0.0.0.0/0`); give a management
CIDR to keep it off the WAN. The manual alternative is `cp .env.example .env`
plus editing it.

The `.env` and, above all, the admin account come **before** `setup-host.sh`:
once the firewall is loaded, the only way in is the portal, and without an admin
account the portal's admin interface is unreachable and host SSH stays closed.

`setup-host.sh` installs nftables, loads the early boot protection, installs the
`dropjak-boot.service` unit, and sets `net.ipv4.ip_forward=1`. In two-NIC mode
it also disables IPv6 on the LAN interface (`net.ipv6.conf.<HV_LAN_IF>.disable_ipv6 = 1`
in `/etc/sysctl.d/90-dropjak.conf`; it reads only the `HV_LAN_IF` line of
`.env` and stops if it is missing). With `HV_SINGLE_NIC=1` it reads
`HV_LAN_IF` only to note that it is ignored, does not require it, and omits the
LAN IPv6 setting. An SSH session over IPv6 gets no
exception: IPv6 is always dropped, so run the installation over IPv4. The boot
protection closes host SSH (TCP 22) for every source; the script keeps the SSH
session that started it reachable until the container loads its rules. After
the first container start the boot table is deleted and the final rules take
over: TCP 22 then needs a portal session plus an assigned TCP 22 input rule, so
the provider console should be open, or the first start should be done with
`HV_SKIP_FIREWALL=1`.

First login after the start: sign in with the admin from `.env`, change the
password, then create a **Host SSH** (input, TCP 22) rule, assign it to the
admin, and authorize it from the same IP.

#### 10.2. Build note
The fail-closed forward chain also blocks the build container's egress, so a
build over Docker's default bridge cannot resolve or reach
`deb.debian.org` (`Temporary failure resolving 'deb.debian.org'`), even though
the Docker daemon itself can pull images. Build the image on the host network
instead:

```bash
DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .
docker compose up -d
```

Do not put `network: host` into the compose build section: Compose builds
through buildx bake and cannot grant the `network.host` entitlement, so
`docker compose up -d --build` stops with `additional privileges requested`.
With BuildKit only, the buildx form grants it explicitly:

```bash
docker buildx build --allow=network.host --network=host -t dropjak:2 --load .
docker compose up -d
```

`--build` should intentionally be omitted if the image is already built. It is worth running the command from a detached script, because the recreate can interrupt SSH. The backups used for the 3.3.0 installation are listed in point 2.2.

#### 10.3. Native installation
```bash
sudo ./install.sh --wan-if eth0 --lan-if eth1 \
     --lan-net 192.168.50.0/24 --gateway-ip 192.168.50.1 \
     --portal-net 0.0.0.0/0 --portal-url http://192.168.50.1
```

Single-NIC host (one interface, the WAN is also the client side):
```bash
sudo ./install.sh --single-nic --wan-if eth0 \
     --portal-net 0.0.0.0/0 --portal-url http://203.0.113.10
```

Without `--lan-if`/`--lan-net`/`--gateway-ip`, the installer asks whether it is
a single-NIC host (default: yes when there is no private IPv4 interface
besides the WAN). In single-NIC mode it requires only `WAN_IF`, skips the LAN
interface, CIDR and gateway checks, leaves the LAN values empty, omits the
LAN IPv6 sysctl line, and writes `HV_SINGLE_NIC=1` into the systemd drop-in
together with the other environment values. In two-NIC mode the behavior is
unchanged.

The installer's supported systems: RHEL/AlmaLinux/Rocky/Oracle Linux 8+, Fedora, Debian 11+, Ubuntu 20.04+, SLES/openSUSE Leap; Python 3.8+ and nftables are required. File locations:

| Path | Content |
|---|---|
| `/opt/hatarvedelem` | Python modules, `index.html`, icons, `services.json`, `VERSION`. |
| `/var/lib/hatarvedelem` | State files (systemd `StateDirectory`). |
| `/etc/nftables/dropjak.nft` | Rendered rules, `0600`. |
| `/etc/systemd/system/dropjak.service` | Portal unit. |
| `/etc/systemd/system/dropjak-firewall.service` | Early firewall unit. |
| `/etc/systemd/system/dropjak-boot.service` | Docker early boot protection (installed by `setup-host.sh`). |
| `/etc/sysctl.d/90-dropjak.conf` | `net.ipv4.ip_forward=1`; `net.ipv6.conf.<LAN_IF>.disable_ipv6=1` in two-NIC mode only. |

The native install does not support the Caddy proxy (`__PROXY__` is always rendered commented out), so it needs no `HV_PROXY_KEY`. The `docker_bridges` set stays empty there; only the `docker*`/`br-*` patterns apply.

The `dropjak-firewall.service` has `DefaultDependencies=no`, `Before=network-pre.target`, and intentionally no `ExecStop`: stopping the service does not open the network. The portal unit depends on the firewall unit with `Requires=`, and uses `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `RestrictAddressFamilies` and similar hardening.

The `deploy/hv` helper is **not** installed by `install.sh`; it is made for Docker Compose and operates on the checkout it lives in (it changes into its parent directory). Run it as `./deploy/hv <command>` from the checkout.

#### 10.4. Upgrade
For Docker:

```bash
git pull
DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .
docker compose up -d --force-recreate
```

Migrating from the old resource names: the image was `hatarvedelem:2`, the
volume `hatarvedelem-state`, and the container, unit and file names started
with `hatarvedelem`. The nftables table name deliberately stays
`inet hatarvedelem`. Stop the old project first (it still owns the old
container and volume), copy the state, then start the new one:

```bash
docker compose down
docker volume create dropjak-state
docker run --rm \
  -v "$(docker volume ls -q | grep -m1 '_hatarvedelem-state$')":/from \
  -v dropjak-state:/to busybox cp -a /from/. /to/
docker compose up -d --force-recreate
```

On a native installation `install.sh` installs `dropjak.service` and
`dropjak-firewall.service`, and disables and removes the old units.

After the recreate the dynamic sets are flushed, so every client must log in and authorize again. The state volume is preserved. In a native installation, re-running `install.sh` updates the files and units; reloading the firewall does not flush the dynamic sets, but the portal's startup flush does.

Before 3.15.1 the upgrade could get stuck: the entrypoint, alongside the old sets without the interval flag, first checked the rendered rules with `nft -c`, so the migration did not even start, the container went into a crash loop, and the `input` chain remained without rules, with `policy drop` (the host became unreachable on every port, including the portal; it worked after a restart, because by then the old table was gone). From 3.15.1 the migration check and the deletion of the old table run before validation; before deletion the early boot protection `deploy/dropjak-boot.nft` (part of the image) is loaded, and it is deleted only after the final rules have loaded successfully. If validation or loading fails after the deletion, the host remains under boot protection, in a fail-closed state.

#### 10.5. Backup and restore
```bash
VOLUME=$(docker volume ls -q | grep -m1 'dropjak-state')
docker run --rm \
  -v "$VOLUME":/data \
  -v "$PWD":/backup \
  busybox tar czf /backup/dropjak-state.tar.gz -C /data .
```

The compose file pins the volume name to `dropjak-state`, so `docker volume ls`
shows exactly that name. The backup contains the `users.json`, `groups.json`, `rules.json`, `audit.jsonl`, `drops.jsonl`, `fail2ban.json`, `firewall-settings.json` files. These may also contain personal data (email) and TOTP secrets, so the backup must be protected as carefully as the live volume.

#### 10.6. SSH lockout and recovery
After installation or restart, host SSH may be closed. Recovery paths:

1. **Portal from the same public IP.** Log in, then authorize a host rule assigned by an admin that contains TCP 22. This is the normal path.
2. **Provider console.** The safest way out; it should always be available before installation.
3. **Breakglass chain.** On the host, from the console:

   ```bash
   nft add rule inet hatarvedelem breakglass \
       ip saddr <your-ip> tcp dport 22 accept
   ```

   After use, the rule must be deleted immediately. The chain survives reload.
4. **`HV_SKIP_FIREWALL=1`.** Only at first start or in an emergency; loading the rules is skipped, but the portal starts. Afterwards a normal start and setting up a host rule.

`docker compose down` does **not** delete the `inet hatarvedelem` table; the network remains closed. Deliberately removing the table:

```bash
sudo nft delete table inet hatarvedelem
```

After that the forward chain no longer protects, so only if another mechanism takes over its role.

#### 10.7. Uninstall / removal
`uninstall.sh` removes a Dropjak installation completely, for both deployment
styles. In a Docker Compose checkout it is run from the repository; the native
`install.sh` also copies it to `/opt/hatarvedelem/uninstall.sh`.

```bash
sudo ./uninstall.sh                 # asks for confirmation (type UNINSTALL)
sudo ./uninstall.sh --yes           # no confirmation
sudo ./uninstall.sh --keep-data     # keep users, rules, settings and certificates
./uninstall.sh --dry-run            # preview, works without root
```

The script stops and disables the systemd units, brings down the
`dropjak0` WireGuard interface, deletes the `inet hatarvedelem` and
`inet hatarvedelem_boot` nftables tables (and nothing else), removes the
Compose stack, its containers, the local `dropjak` image tags and the volumes
(`dropjak-state` plus the project-scoped Caddy volumes), then removes
`/opt/hatarvedelem`, `/var/lib/hatarvedelem`, `/run/dropjak`, the nftables and
sysctl files, and finally the `hatarvedelem` system user and group. The
installation directory containing the script is removed last, together with
the script itself; a directory that does not contain a Dropjak marker file
(`docker-compose.yml`, `install.sh`, `configure.sh` or `server.py`) is refused.

`--keep-data` preserves the `dropjak-state` Docker volume and
`/var/lib/hatarvedelem` (and therefore the account that owns the state
directory); everything else is still removed. Backups in
`/root/hatarvedelem-backups` are always kept. Missing containers, units,
tables, files and accounts are skipped with a note, so a repeated run is safe.

#### 10.8. Update
`update.sh` updates a checkout in place: it first backs up the configuration
and the runtime state, then runs a fast-forward-only git pull. The backup
never goes into the repository. It is written to `/root/dropjak-backups`
(mode 0700, archives 0600); the script refuses to run when `HV_BACKUPS`
resolves to the checkout or a directory below it.

```bash
sudo ./update.sh                    # asks for confirmation (y/N)
sudo ./update.sh --yes              # no confirmation
./update.sh --dry-run               # preview, works without root
HV_BACKUPS=/srv/backups sudo -E ./update.sh
```

The configuration backup `dropjak-<timestamp>.tar.gz` contains a copy of
`.env` as `env`, `secrets/`, and the `dropjak.service.d` systemd drop-in when
present. The state is written as `dropjak-state-<timestamp>.tar.gz` from the
Docker volume `dropjak-state` and/or `dropjak-state-native-<timestamp>.tar.gz`
from `/var/lib/hatarvedelem`. If neither state directory exists, the
configuration backup is still created and a warning is printed. The script
never prints the contents of `.env` or the secrets.

The git step is `git pull --ff-only`; nothing is stashed, reset, checked out
or discarded, so a dirty checkout or a diverged branch fails cleanly with the
backup intact. After a successful pull the script only prints what is needed
for the deployment to take effect; it does not run it:

```bash
# Docker deployment (host-network build), or: sudo deploy/hv rebuild
DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .
docker compose up -d --force-recreate

# Native deployment: re-run the installer with the same arguments
sudo ./install.sh <the original arguments>
```

The native `install.sh` copies the script next to the other installed files
with mode 0755.

### 11. Testing
#### 11.1. Local unit and API tests
The full suite in the 3.24.0 local working directory is **985 tests**, all OK. Running it in the repository's usual way:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The result of the 2026-10-23 run: 985 tests OK (119 s). The syntax check of the portal's inline JavaScript (`node --check`) is also OK.

The new test groups of 3.24.0: the multi-port schema and per-index pairing of lists/ranges (`test_tunnels`, `test_tunnel_ui`), mapping expansion and `both` merging (`test_tunnels`, `test_tunnel_agent`), resolution of service rules, their collection membership and fail-closed behavior (`test_gateway`, `test_tunnels`), atomic rewrite and audit of direct `users`/`groups` assignment (`test_tunnels`), lifecycle limits of the referenced service/agent (`test_tunnels`), WAN-only pre-auth rules of public port services and their absence in private/domain/disabled cases (`test_tunnels`), validation of domain services, automatic internal port allocation in the 41000–60999 range and its collision handling (`test_tunnels`), domain target resolution, public/private `/api/proxy/auth` behavior and domain-rule lifecycle limits (`test_tunnels`), as well as the single-network home agent installer and containment check (`test_tunnel_agent`). The admin protection of the service availability test, rejection of unknown/disabled targets, TCP success/rejection/timeout and UDP silence/ICMP cases, the four-mapping limit and concurrency, and the secret-free audit are covered by `test_tunnels`; the single-form panel and the markers of the Test button are covered by `test_tunnel_ui`. Allowing disabling of the referenced service/agent, fail-closed access and session revocation, as well as admin protection, read-only nature and `last_sync` calculation of `GET /api/admin/tunnels/status`, are checked by `test_tunnels`; the status refresh button, the active/disabled pill and the inline error markers are checked by `test_tunnel_ui`.

Test files and counts:

| Test file | Tests | Focus |
|---|---:|---|
| `tests/test_gateway.py` | 436 | Session/grant/TTL/union/revoke/HTTP/CLI basic behavior; service rule resolution and authorization; session domain of a domain-mode service and revocation on rename. |
| `tests/test_tunnels.py` | 78 | Multi-port schema, lists/ranges, expansion and `both` merging, migration, service rules, assignments, lifecycle limits (disabling fail-closed, deletion forbidden), bundle; public port service pre-auth rules, domain service, internal port allocation; service availability test; status endpoint and `last_sync`; challenge of a domain service; proxy access of a domain-mode service, and its rename with a UI payload while the internal listen port is unchanged, and session revocation. |
| `tests/test_live_cli.py` | 40 | CLI commands, daemon connection, local fallback. |
| `tests/test_proxy.py` | 39 | Domain proxy, routes, visibility. |
| `tests/test_port_proxy.py` | 32 | Port proxy entries, DNAT, collisions. |
| `tests/test_tunnel_agent.py` | 55 | Agent wire format, one port/listener entry, nft rules, configuration; single-network installer and containment check. |
| `tests/test_revocation.py` | 29 | Revocation, durability, conntrack, restart. |
| `tests/test_fail2ban_drop_metrics.py` | 25 | Three independent signals, threshold migration, ban release, event store, env defaults, audit breakdown. |
| `tests/test_port_ranges.py` | 24 | Port ranges, overlap, forbidden ports. |
| `tests/test_proxy_certs.py` | 22 | Certificates, ACME, expiry. |
| `tests/test_proxy_challenge.py` | 21 | Proxy challenge, captcha, pass cookie. |
| `tests/test_audit_search.py` | 20 | Audit filtering, normalization, API. |
| `tests/test_fail2ban_proxy.py` | 17 | Proxy-based fail2ban signal. |
| `tests/test_host_service_guard.py` | 17 | Host service guard, port prune, capacity. |
| `tests/test_block_generation.py` | 15 | Block/pre-auth generation, validation. |
| `tests/test_caddy_admin.py` | 12 | Caddy admin API, reload. |
| `tests/test_revocation_lock_scope.py` | 12 | Lock scope, concurrent authorization/revocation. |
| `tests/test_audit_ui.py` | 11 | Audit UI event selector, filters. |
| `tests/test_access_bulk_ui.py` | 4 | Select all / Max buttons, HU/EN/DE labels, selection limit and node check of the maximum hour count. |
| `tests/test_block_precedence.py` | 9 | Block precedence, pre-DNAT, atomicity. |
| `tests/test_fail2ban_consistency.py` | 8 | fail2ban state and persistence. |
| `tests/test_propagation_multi.py` | 7 | Multiple selection, partial revocation, directions. |
| `tests/test_proxy_redirect.py` | 7 | HTTP → HTTPS and portal redirect. |
| `tests/test_tunnel_ui.py` | 11 | Multi-port editor, client-side validation, service rule UI, domain-mode service in the selector, Test button and single-form agent panel, status refresh button/active pill/inline error, HU/EN/DE. |
| `tests/test_installer.py` | 6 | Installer file list, placeholders, units. |
| `tests/test_portproxy_netns.py` | 1 | Port proxy network namespace E2E. |

#### 11.2. Live E2E
The gated scenarios of `tests/e2e_vm.py`:

| Switch | Scenario |
|---|---|
| `HV_E2E_LONG` | Longer, slower live processes. |
| `HV_E2E_PENDING` | Approval/rejection of a pending account. |
| `HV_E2E_RESTART` | Restart and re-authorization. |
| `HV_E2E_MULTI` | Multiple rule selection. |
| `HV_E2E_RULES` | Rule modification and propagation. |

The live manual check of multiple selection was performed (`ssh,mpwerks`). The automated run of `HV_E2E_MULTI` **has not yet taken place**. The current live status of the other gated scenarios cannot be determined from this document: **NOT VERIFIED**.

#### 11.3. What the tests do not cover
- Real kernel nft/conntrack/NFLOG behavior is proven only by a live VM run; a significant part of the test suite works with mocked nft.
- ARP/MAC resolution and switch-level spoofing cannot be fully simulated in a unit test.
- The race between the Docker `DOCKER-USER` guard and the boot table requires a live environment.
- The multi K6 scenario and the long-running restart scenarios have not yet produced live results.

### 12. Version history
The complete, detailed entries are in the [7. Changelog](#valtozasnaplo) section. The table below summarizes the main milestones.

| Version | Date | Main change |
|---|---|---|
| 2.0.0 | 2026-10-19 | First release: nftables captive portal, Docker host network, trilingual UI, two-phase login, fail-closed forward. |
| 2.0.1 | 2026-10-19 | Admin form preserves values after a validation error; address simplification; README rewrite. |
| 2.1.0 | 2026-10-19 | Spoofing/portal-bypass hardening, NFLOG drop log, custom pre-auth/block, raw/visual firewall view, dark theme. |
| 2.2.0 | 2026-10-20 | fail2ban login- and drop-based banning, ban screen, drop log source/destination breakdown, six reason groups. |
| 2.3.0 | 2026-10-20 | Design de-slop, type scale, contrast, pills; pre-de-slop snapshot. |
| 2.4.0 | 2026-10-20 | Optional TOTP 2FA with QR enrollment; self-service account requests with admin approval. |
| 2.5.0 | 2026-10-20 | Collection rules, rule duplication, password generator; host SSH tied to `admin-full`. |
| 2.6.0 | 2026-10-20 | Whole-hour TTL, at most 30 days. |
| 2.7.0 | 2026-10-20 | Forward/input direction, `allowed_input_*` sets; audit log. |
| 2.8.0 | 2026-10-20 | Mixed-direction collections without their own direction; per-direction enforcement. |
| 2.9.0 | 2026-10-20 | Version tracking (`VERSION`, `CHANGELOG`, portal footer, `/api/status`). |
| 2.10.0 | 2026-10-20 | Configurable firewall name; loud lockout warnings. |
| 3.0.0 | 2026-10-20 | Removal of `admin-full` and `host_ssh_v4`; host SSH only with an explicit input rule. |
| 3.0.1 | 2026-10-20 | Native installer installs every module and asset; seven nft placeholders; drop-in. |
| 3.0.2 | 2026-10-20 | Durable revocation, startup reconciliation, block precedence, host-service guard, CLI daemon path, lock scope. |
| 3.1.0 | 2026-10-21 | Multiple rule selection, partial revocation, stricter TTL, multiple API/UI/audit, K6 gate. |
| 3.2.0 | 2026-10-21 | Independent fail2ban drop metrics, threshold 0, audit event selector and value-based search, live UI update, TTL hint. |
| 3.2.1 | 2026-10-21 | Local, not yet deployed: the "hour" unit label for the duration and elimination of the TTL hint repetition. |
| 3.3.0 | 2026-10-21 | Live: the three fail2ban signals (login, packet count, destination ports) with a fully independent switch; rejection of the 0 threshold and migration of saved 0; removal of the drop master switch; independent ban release. |
| 3.3.1 | 2026-10-21 | Local, not yet deployed: the shared ban length in the non-switchable "Common settings" group; the reversed key of the validation message; saving an empty/disabled field with the saved value; `login_count`/`drop_count` in the audit; stronger tests. |
| 3.24.0 | 2026-10-22 | Multi-port tunnel services (lists/ranges, per-index pairing, `both` merging, global listen uniqueness, automatic migration); `service_refs` service rules; direct `users`/`groups` rule assignment; service editor and service rule selector in the UI; playit.gg-like, one-command home agent installer with interactive, numbered network selection (exactly one network; `DROPJAK_NETWORK` / `DROPJAK_NO_PROMPT` for non-interactive mode) and a `delete` operation; label/id-based unique agent container name and multiple agents on one host; public port services with WAN-only pre-auth rules; domain (behind Caddy) tunnel services with automatic internal port allocation and domain-rule lifecycle limits; service availability test for the full portal→WireGuard→DNAT path, and a redesigned agent/service list with one form open at a time; fail-closed behavior of disabling even with a reference, while deletion remains forbidden; agent status refresh (`GET /api/admin/tunnels/status`) and active/disabled/online/offline indication; removal of the "active" tick in the service editor (state handled by the row switch); challenge management of domain tunnel services on the Domains tab; the domain rule selector also offers tunnel domains; the service test result disappears after 60 seconds; the row switch for a domain service does not clear the target port (the partial payload preserves the mapping); 973 tests. |

### 13. Progress and open points
#### 13.1. Done and live
- The 3.3.0 image runs on the VM; `/api/status` `ok: true`, version `3.3.0`; the running image digest is (digest in private notes).
- The 3.3.0 live:
  1. the three fail2ban signals (failed login, dropped packets, distinct destination ports) work with a fully independent switch;
  2. the 0 threshold is gone: `drop_max`/`drop_ports` are at least 1, and a saved 0 is migrated;
  3. removal of the drop master switch and per-signal ban release are live;
  4. the 3.2.0 live UI update, TTL hint, audit event selector and value-based search are still part of the image.
- The recreate closed host SSH because the dynamic sets were flushed; re-authorization happens on the portal.
- The live manual check of multiple selection was performed.
- The local full test suite in the 3.24.0 working directory is 985 tests OK; the JS syntax check is OK.
- The backups before the 3.3.0 installation are available.
- The integrity of `.env` did not change before the recreate; `.secret` was not present on the VM.
- The local 3.3.1 fixes (shared ban length, validation message, empty/disabled field, audit breakdown) are **not yet live**.

#### 13.2. Local code, but without live confirmation
- The seven regression tests of `tests/test_propagation_multi.py` run locally, but the live automated `HV_E2E_MULTI` variant does not.
- The git working directory is not clean; the identity of local and live code is not verified bit-for-bit.
- Some of the residual runtime assumptions described by the [3.5 Propagation matrix](#propagacios-matrix) could be closed only with live measurement.
- The 3.3.1 fixes are tested locally, but do not run on the VM.

#### 13.3. Plan / deferred
- **Multiple site settings.** According to the snapshot, the developer's home `todo.txt` file now contains only this deferred item; the details must be discussed with the user. This document does not decide on it.
- **Caddy / TLS reverse proxy.** The plan in the [4.1 Domain proxy plan](#caddy-proxy-terv), whose status is literally "plan — not implemented". The portal is currently plain HTTP; if it is reachable from the WAN, `HV_COOKIE_SECURE=1` protects only the cookie, not the password and TOTP data. Narrowing `HV_PORTAL_NET` or TLS termination is necessary.
- **Live E2E coverage.** The result of the K6 multi scenario and the other gated live scenarios is still missing.
- **Email notification / extension of the account request flow.** Email is only contact data; there is no sending, verification, cancellation, expiry or bulk operation.

#### 13.4. Unverified points
- The VM container's uptime, container ID, PIDs; the file-level contents and restorability of the two backup archives.
- The live E2E result of K1–K5; the git commit/push state and the bit-for-bit identity of the local and live source.
- The actual values of `.env` (only the hash is known; the content was intentionally not read).
- The detailed configuration of the Minecraft container running on the VM (only the `172.30.0.2` exception of the nft template is visible in the repo), and the state of the native `install.sh` units on the Docker VM.

### 14. File map
| Path | Role |
|---|---|
| `VERSION`, `DOKUMENTACIO.md` ([7.](#valtozasnaplo)) | Version and version history. |
| `README.md`, `DOKUMENTACIO.md` ([1.](#projekt-allapot)) | User and project status documentation. |
| `server.py` | HTTP API, portal, admin, auth. |
| `gateway.py` | Rules, sessions, nft calls, revocation. |
| `fail2ban.py`, `droplog.py` | Banning and NFLOG-based drop log. |
| `settings_store.py` | Settings validation, atomic write. |
| `index.html`, `icon.png`, `blocked.png` | Portal/admin UI and assets. |
| `services.json` | Service catalog (empty `scenarios` list: no initial rules). |
| `docker-compose.yml`, `Dockerfile` | Docker host network, state volume, healthcheck, image. |
| `install.sh`, `.env.example`, `.dockerignore`, `.gitignore` | Native installer, configuration sample, Docker and git exclusions. |
| `configure.sh` | Interactive `.env` generator (installation mode, interfaces, networks, portal source, access mode, admin account). |
| `docker/entrypoint.sh` | Env validation, rendering, nft, set flush, boot table, Docker guard, watchdog, setpriv. |
| `docker/setup-host.sh` | Boot nft/unit and `ip_forward` on the host. |
| `deploy/dropjak.nft` | Complete nftables template with seven placeholders. |
| `deploy/dropjak.service`, `deploy/dropjak-firewall.service`, `deploy/dropjak-boot.service`, `deploy/dropjak-boot.nft` | Systemd units and the early boot table. |
| `deploy/hv`, `DOKUMENTACIO.md` ([2.](#telepites)) | Docker operational helper and local guide. |
| `DOKUMENTACIO.md` ([3.6](#audit-naplo), [3.3](#host-szabalyok)) | Audit and host/SSH rules. |
| `DOKUMENTACIO.md` ([3.5](#propagacios-matrix), [3.4](#gyujtoszabalyok)) | Invariants/mutation matrix and collection semantics. |
| `DOKUMENTACIO.md` ([3.2](#totp-2fa), [3.1](#fiokigenyles)) | 2FA and account requests. |
| `DOKUMENTACIO.md` ([4.1](#caddy-proxy-terv), [6.1](#antislop-terv), [6.2](#design-backup-notes)), `docs/design-backup-2026-10-20/` | Plans and design snapshot. |
| `tests/test_gateway.py`, `tests/test_live_cli.py`, `tests/test_revocation*.py` | Basic, CLI, revocation and lock scope. |
| `tests/test_host_service_guard.py`, `tests/test_block_*.py` | Host guard and block/pre-auth. |
| `tests/test_fail2ban_*.py`, `tests/test_audit_*.py` | fail2ban and audit. |
| `tests/test_propagation_multi.py`, `tests/test_installer.py`, `tests/e2e_vm.py` | Multiple selection, installer, live E2E. |

The list of open tasks lives not in the repo but in the developer's home
`todo.txt` file (outside the repository).

### 15. Quick commands and troubleshooting
#### 15.1. Status and logs
```bash
# Docker
docker compose ps
docker compose logs -f dropjak
curl -fsS http://127.0.0.1:8100/api/status | python3 -m json.tool

# With the deploy/hv helper (Docker, from the checkout)
./deploy/hv status
./deploy/hv logs
./deploy/hv restart
./deploy/hv backup
./deploy/hv test
./deploy/hv e2e
./deploy/hv where
```

The `hv` commands according to the snapshot: `status`, `logs`, `restart`, `rebuild`, `edit`, `services`, `users`, `add`, `passwd`, `del`, `backup`, `test`, `e2e`, `where`.

#### 15.2. Firewall check
```bash
sudo nft list table inet hatarvedelem
sudo nft list set inet hatarvedelem allowed_tcp
sudo nft list set inet hatarvedelem allowed_input_tcp
sudo nft list set inet hatarvedelem banned_v4
sudo conntrack -L | head
sudo nft list table inet hatarvedelem_boot   # only during boot
```

The `host_service_tcp` / `host_service_udp` only grow; if a port remains there, that is not an error in itself, it only means stricter established checking.

#### 15.3. Common errors
| Symptom | Likely cause | Action |
|---|---|---|
| `docker compose build` cannot reach a mirror, or stops with `additional privileges requested` | The fail-closed forward chain blocks the build container's egress, and Compose cannot grant BuildKit the `network.host` entitlement. | `DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .`, then `docker compose up -d --force-recreate`. |
| SSH interrupted after installation | The startup flush cleared `allowed_input_tcp`. | Portal from the same IP, or provider console, or breakglass. |
| The portal does not start | Missing mandatory env, faulty CIDR, nft error, state file error. | `docker compose logs`; check `HV_LAN_IF`, `HV_WAN_IF`, `HV_LAN_NET`, `HV_PORTAL_NET`. |
| The portal is reachable, but the network is not | No valid grant, expired TTL, fail2ban, block, MAC mismatch. | `/api/status`, admin Sessions/Firewall, `nft list set`, `conntrack`. |
| Host SSH does not open | No explicit host rule containing TCP 22, or no active session. | Admin Rules/Users; host rule and assignment; portal login from the same IP. |
| The drop log is empty | `HV_DROP_LOG=0`, wrong NFLOG group, another consumer, missing kernel NFLOG. | `HV_DROP_LOG=1`, group match, `dmesg`/`journalctl`. |
| fail2ban banned its own IP | Threshold too low, scanner behind NAT, manual ban. | Console + `server.py fail2ban unban <ip>` or `unban-all`; raise the threshold. |
| The user logs in but does not get access | pending account, disabled account, wrong TOTP, `must_change_password`, no rule selected. | Admin Users; pending approval; TOTP reset; password change; rule selection. |
| The user cannot even log in | pending account, disabled account, wrong password/TOTP, captcha error, fail2ban. | Admin Users; pending approval; TOTP reset; release the ban. |
| The admin UI does not refresh | Old rule snapshot, revoked selection. | In 3.2.0 the 30-second poll refreshes; **Modify** requests fresh status. |
| `permission denied` for nft | The container did not get `NET_ADMIN`, or wrong capability in native mode. | Compose `cap_add`, systemd `AmbientCapabilities`. |

#### 15.4. Diagnostic principles
- First look at the portal's own state (`/api/status`, admin Sessions/Firewall), only then the kernel.
- The kernel set and the portal's session table may differ: the set's TTL is authoritative for traffic, the session for the UI.
- Do not run `nft flush ruleset`: it would delete all chains, not only your own.
- Modifying `block` does not require a conntrack flush; revoking a grant does, but the portal performs it.
- After the `breakglass` rule, do not forget to delete the rule.

### 16. Appendix: concepts
| Concept | Explanation |
|---|---|
| **Captive portal / fail-closed** | Login page; on error or missing configuration the system remains closed. |
| **nftables / set / timeout** | Kernel-side filter-NAT framework; set elements have kernel-side expiry. |
| **Forward / input (host)** | Traffic passing through the gateway, respectively traffic toward the gateway machine itself. |
| **DNAT / pre-DNAT** | Destination address translation; the grant and the block look at the original, pre-DNAT destination. |
| **Conntrack** | Connection tracking table; on revocation the existing flows must also be deleted. |
| **MAC binding / TTL / grant** | The authorization is bound to the IP and the MAC resolved from ARP, with a TTL; the grant is the concrete kernel elements. |
| **Collection** | The union of several individual rules; it has no own direction and ports. |
| **Proof-of-work / Turnstile** | Local captcha with a computational task, respectively optional Cloudflare captcha. |
| **TOTP / recovery code** | Time-based 6-digit code, respectively a single-use backup code. |
| **NFLOG / drop log** | Netfilter logging to a netlink group; the header-only JSONL log is built from it. |
| **fail2ban** | Here the built-in one, not the classic daemon: login- and drop-based banning. |
| **Breakglass / DOCKER-USER** | Emergency SSH chain that survives reload, respectively Docker's user chain. |
| **Watchdog / dry run** | The entrypoint's firewall watchdog; with `HV_DRY_RUN=1` the portal does not write nft. |

### 17. Document changelog
| Date | Change |
|---|---|
| 2026-10-21 | First release. Based on the 3.2.0 snapshot, the local repository and the specified live facts. The document contains no secrets; uncertain points were marked "NOT VERIFIED". |
| 2026-10-21 | Review pass: the `git clone` and backup command, the audit Logs filters, the rule-TTL examples, the forward chain order, the location of `todo.txt` and the file map were refined. |
| 2026-10-21 | 3.2.1: fix of the duration hour label and the TTL hint repetition; the document marks live 3.2.0 / local 3.2.1 state. |
| 2026-10-21 | 3.3.0: independent switching of the three fail2ban signals, elimination of the 0 threshold and migration of the old 0; the document marks live 3.2.0 / local 3.3.0 state. The change is local only, not deployed. |
| 2026-10-21 | 3.3.1: live installation of 3.3.0 (image `sha256:55b1…`, `/api/status` 3.3.0, backups `20261021-153034`); the local tree is 3.3.1, which contains the shared ban length, the validation message, saving of the empty/disabled field, the audit breakdown and stronger tests, but is not deployed. Live 3.3.0 and local 3.3.1 are listed separately. |
| 2026-10-22 | 3.24.0: documentation of the multi-port tunnel services, the WAN-only pre-auth rules of public port services, the domain (behind Caddy) tunnel services with automatic internal port allocation and domain-rule lifecycle limits, the `service_refs` service rules and the direct `users`/`groups` assignment; documentation of the service availability test and the redesigned agent/service list; sections 3.8, 3.4, 3.5, 6.3, 7.3, 7.6, 8.1, 8.3, 11.1 and 12 updated; the header and configuration example version is 3.24.0; measured test suite 973 tests; the fail-closed semantics of disabling and the status refresh button documented; the tunnel domains of the domain rule selector and the automatic disappearance of the test result after 60 seconds documented. |
| 2026-10-23 | Domain-mode service in a service rule: `service_refs` can be saved without a port, the session reaches the domain through the proxy gate via `session_domains`; fail-closed disabling, domain rename revokes even with an unchanged internal listen port because of the signature and the domain row of the effective mapping, a mixed rule keeps the ports; the `services` payload gets a `domain` field, the `ports_label` is "Service: <label> (<domain>)"; the UI selector offers domain-mode services with the ` · Domain` marker; `RuleSelection` preserves the `service_refs`/`service_domains` fields; 5 `test_gateway`, 2 `test_tunnels` and 1 `test_tunnel_ui` tests added, the measured suite is 981 tests. |
| 2026-10-23 | Access selector quick buttons: **Select all** in the rule list header (up to the `limits.max_rules` limit, idempotent when repeated, preserving the existing order), **Max** next to the TTL field (`floor(min(limits.max_ttl, max_ttl of selected rules) / 3600)`, clamped to the field's minimum); the `/api/status` `limits` also sends the `max_rules` value; HU/EN/DE labels and aria text; 4 new tests in `test_access_bulk_ui`, the measured suite is 985 tests. |
| 2026-10-23 | Full documentation translated into English (README and this file); obsolete `docs/*.md` and AI progress notes removed, their content is kept in the merged sections here; duplicate/local artifacts deleted. Test counts unchanged (985). |

<a id="telepites"></a>

## 2. Installation and operations

_Source: `deploy/HELYI-UTMUTATO.md` (original title: "Where to edit what")._

> This guide belongs to the Docker Compose installation. The native `install.sh`
> does not install the `hv` command (it builds on the `/root/hatarvedelem` checkout and the
> Docker volumes); in a native installation, `systemctl` and
> `/opt/hatarvedelem/server.py` can be used.

The project is here: `/root/hatarvedelem`. Most of the time you need to touch **two files**. There is a short command for everything, you do not need to search in the Docker folders.

### Quick commands

```bash
hv status      # is the container running, is the portal up, what is in the nft sets
hv logs        # logs live (Ctrl+C to exit)
hv restart     # restart so the new .env values take effect
hv rebuild     # rebuild if the code or services.json changed
hv where       # this page
```

### 1. Settings — `.env`

> **WARNING — you can lock yourself out of the host.** Loading the firewall
> interrupts the current SSH connection if there is no active, authorized
> portal session from that source IP and no host rule explicitly
> allowing TCP port 22. Before the first start, set up the admin account
> (`HV_ADMIN_ENABLED=1`, `HV_ADMIN_USER`, and `HV_ADMIN_PASSWORD` or
> `HV_ADMIN_PASSWORD_FILE`). Without an admin account you cannot log in to
> the portal, so the **Admin** panel is unreachable and host SSH remains
> closed. Keep the provider console available: if the `breakglass` chain
> cannot be used, you can restore access through it.

```bash
hv edit        # opens in nano; afterwards: hv restart
```

Here are the network interfaces, the portal port, the admin account, the TTL and the
proof-of-work difficulty. The file's permissions are `0600`, because the admin password
is stored in it as plain text.

The most common lines:

| Line | What it means |
|---|---|
| `HV_SINGLE_NIC` | `1`: single-NIC host; `HV_WAN_IF` is also the client side and `HV_LAN_IF`/`HV_LAN_NET` are ignored |
| `HV_LAN_IF` / `HV_WAN_IF` | internal and external interface name (`ip -br link`); the LAN line is two-NIC only |
| `HV_LAN_NET` | the served internal network (two-NIC only) |
| `HV_PORTAL_NET` | the network from which the portal is reachable; `0.0.0.0/0` = from anywhere |
| `HV_MGMT_NET` | management network for fail2ban exemptions; it does not narrow the portal and does not allow SSH |
| `PORT` | the portal port on the host (port 80 is redirected here) |
| `HV_ADMIN_ENABLED` | `1`: creates/updates the admin account at startup |
| `HV_ADMIN_USER` / `HV_ADMIN_PASSWORD` | the admin account details |
| `HV_SESSION_TTL` | the initial value of the time the user can select |
| `HV_AUDIT_MAX_BYTES` / `HV_AUDIT_KEEP` | the audit log rotation size and the number of files kept |

**Admin password change:** `hv edit`, then `hv restart`. Changing the `.env` password
resets the admin password and requires a mandatory change at the next login. If you
changed the password on the portal, it remains after the restart. `HV_ADMIN_ENABLED=0`
does not delete the account, it only does not deal with it. Manage the other users, groups
and access rules on the portal's **Admin** panel.

In the **Admin → Settings → Firewall name** field you can give the
firewall a name. The name appears in the portal header, in the browser title and in the
authenticator entry of new 2FA enrollments; when empty, the name `Dropjak`
is valid. The change affects only new enrollments; it does not rename
existing authenticator entries.

### Prerequisite for using a domain

For the domain proxy (`HV_PROXY=1`, `COMPOSE_PROFILES=proxy`, **Admin →
Domains**), every root domain needs two DNS A records, both pointing to the server's
public IPv4 address:

| Record | Value |
|---|---|
| `A <root>` (e.g. `z1.example.com`) | the server's public IP |
| `A *.<root>` (e.g. `*.z1.example.com`) | the same IP |

- On Cloudflare both must be **DNS only** (grey cloud), otherwise Caddy does not
  see the real client IP.
- There must be no AAAA record: incoming IPv6 is dropped by the firewall.
- For the challenge of an unknown subdomain (e.g. `x.z1.example.com`, which is not
  an entry), an uploaded wildcard certificate covering the `*.<root>` name is
  needed (**Admin → Settings → Domain settings**); ACME
  never requests a certificate for an unknown name.
- When **Automatic certificate** is turned off, the portal restarts Caddy
  through its admin socket (`caddy-admin` volume, Unix socket only, no TCP port)
  so that it does not serve the Let's Encrypt certificates in memory either. This is at most a few seconds of outage; open connections
  are interrupted. With ACME enabled, uploading a certificate also
  triggers a restart. The issued certificates remain in the `/data` volume,
  and come back without re-request when re-enabled. Caddy's status (reachable,
  last restart, error) is visible in the same section. The Compose
  `restart: unless-stopped` setting is required for this; do not remove it.

### SSH to the host

Host SSH (TCP 22) is opened **only if** you have logged in on the portal from the same
IP address and authorized a host (`input`) rule created by an administrator that
explicitly lists TCP port 22 (in the
`allowed_input_tcp` set). UDP 22 is an ordinary host port, not SSH.

An active, authorized portal session is required from the same IP address. A single
full-access rule does not open it; a collection can open it only through an input member
that explicitly contains TCP 22. Entering the password
alone does not open it. On logout it closes immediately; on expiry it closes with the
kernel timeout. The browser and SSH should start from the same network
(with a VPN, the same exit IP).

If you have locked yourself out, from the provider console temporarily add the
line indicated in the comment in the input chain of `deploy/dropjak.nft`, reload
the rules, and then remove it.

### 2. Service catalog — `services.json`

```bash
hv services    # edit; afterwards: hv rebuild
```

Rules are now **port-based**: on the admin interface you specify TCP/UDP ports,
ICMP or full access, and a rule can contain several ports. `services.json` holds the `services` catalog used for
automatic port conversion of the earlier, service-based `rules.json`. Its
`scenarios` list is **empty**: a new installation starts with **no rules at all**
and the admin creates them on the **Admin → Rules** page. Later rules must be managed there too. The Dockerfile copies the file
into the container, which is why `hv rebuild` is needed afterwards.

### Users, groups, rules

The primary interface is the **Admin** panel on the portal. There you can create
users, set the role (`admin`/`user`) and the enabled state, assign direct rules and groups, and manage
the groups and rules. Rules, groups and members are selected in a searchable list (there are no many small checkboxes). On the **Rules**
form, TCP and UDP ports must be given separated by commas or spaces; an item can also be a port range (`22, 80, 8000-8100`). The interface
validates while typing, the cards show the range as `TCP 8000–8100`,
and the search also finds a port within the range. A rule
can contain several ports and can give ICMP or full access. For a container published by Docker, the host port must be
entered. The duration on the portal can be given in whole hours.

On the **Logs** tab every event can be filtered, and on the **Sessions** tab
the open sessions and the remaining time are visible; there **Terminate** immediately tears down a session, while **Lock** disables
the user and closes all their sessions. The **Firewall** tab shows the kernel's
actual state grouped by IP address: the open
TCP/UDP ports, ICMP and host TCP 22 (SSH) like the other
host entries, the remaining time per port, as well as the
match with sessions (missing/unexpected port, or a kernel entry without a
session). The view is read-only.

A password set or reset by the admin must be changed by the user at first
login. Disabling and password reset immediately close the user's running sessions. Only one session per IP is active at a time: a new login from the same IP closes
the previous one.

Emergency CLI (creates only the `user` role, assigns no rule):

```bash
hv users           # list
hv add alice       # new user, prompts for password; change at first login
hv passwd alice    # password change; change at first login
hv del alice       # delete
```

The mandatory change at first login can be disabled: `hv add alice --no-must-change`,
respectively `hv passwd alice --no-must-change`.

State is in the Docker volume
(`/var/lib/docker/volumes/dropjak-state/_data/`):
`users.json`, `rules.json`, `groups.json`, `audit.jsonl` (and their rotated
versions). **Do not** edit these by hand — the UI and the CLI manage them.
The files have 0600 permissions.

### Backup and restore

```bash
hv backup          # project + full state to: /root/hatarvedelem-backups
```

Two archives are created: the project (`dropjak-*.tar.gz`, together
with `.env`) and the full state (`dropjak-state-*.tar.gz`: users,
rules, groups, audit log). The directory is `0700`, the files `0600`.
To restore, stop the container, unpack the project archive under
`/root`, and the state archive into the
`/var/lib/docker/volumes/dropjak-state/_data/` directory,
then `hv restart`.

### Tests

```bash
hv test       # quick unit/HTTP tests (outside the container)
hv e2e        # full end-to-end test from the hvclient namespace
```

The e2e builds on the `hv-lan` veth pair and the `hvclient` namespace; it takes about 2 minutes and
temporarily creates a `claudetest` user, which it deletes at the end.

### Important locations

| Path | What is there |
|---|---|
| `/root/hatarvedelem/.env` | the live settings (must not be world-readable) |
| `/root/hatarvedelem/services.json` | service catalog used for port conversion of old rules (no initial rules: the scenarios list is empty) |
| `/root/hatarvedelem/README.md` | detailed description, operations, troubleshooting |
| `/root/hatarvedelem/deploy/dropjak.nft` | the nftables template |
| `/root/hatarvedelem-backups/` | backups |
| `/etc/systemd/system/dropjak-boot.service` | boot protection (fail-closed startup) |
| `/var/lib/docker/volumes/dropjak-state/_data/` | users, rules, groups, audit log |

### If something does not work

1. `hv status` — is the container running, is the portal responding.
2. `hv logs` — the log of the portal and nft loading.
3. `hv restart` — re-reading `.env`.
4. If the code or `services.json` changed: `hv rebuild`.
5. Restore: unpack the selected archive from `hv backup`, then `hv restart`.

<a id="funkciok"></a>

## 3. Features

<a id="fiokigenyles"></a>

### 3.1 Account requests

_Source: `docs/account-requests.md` (original title: „Account requests”)._

**Date:** 2026-10-20

**Status:** implemented and committed as `c88b912`, deployed to the test VM
on 2026-10-20. The feature is disabled by default; the test portal has it
enabled.

This document describes the optional self-service account request feature.
The behavior below is the implementation contract; it is disabled by default.

#### Behavior

Self-registration is controlled by an admin toggle and is **off by default**.
When it is off, the login page does not show the **Fiók kérése** (Request
account) button and `POST /api/register` returns `registration_disabled`.

When it is on, the login page shows the **Fiók kérése** button. The form asks
for a login name, password, password confirmation and email address. The
password confirmation exists only in the UI; the API receives one password
field.

A successful request creates a **pending** account with `pending=true`,
`enabled=false`, `rules=[]`, `totp_required=false`,
`must_change_password=false` and role `user`. No session or cookie is
created. A pending account cannot sign in, authorize network access, be
assigned rules or appear in admin user counts. It is a record waiting for an
admin decision, not an active account.

A sign-in attempt checks the password first. A correct password for a pending
account returns a distinct "awaiting admin approval" message; a wrong password
keeps the generic "invalid username or password" response. Neither creates a
session.

Pending state is fail-closed: a missing `pending` field means `false`, while
any malformed value (for example a string or a number) parses as `true`. A
corrupted record therefore stays pending instead of becoming active.

#### Data model

User records live in `users.json` in the `dropjak-state` volume
(`/var/lib/hatarvedelem/users.json`, mode `0600`). Registration adds two
stored fields:

| Field | Type | Meaning |
|---|---|---|
| `pending` | boolean | Created by a public request and not yet approved. Missing means `false`; a malformed value parses as `true`. |
| `email` | string | Contact address from the request. Trimmed, lowercased, at most 254 characters. Never returned to the requester and never logged. |

The password uses the existing PBKDF2-HMAC-SHA256 record (per-user salt,
iteration count and hash); the plaintext is never stored. Other fields are the
normal user fields with the pending values above.

The admin user representation (`public()`) exposes both `pending` and `email`.
Unauthenticated payloads never expose either. Password material, TOTP secrets
and recovery-code hashes remain hidden as before.

#### API endpoints

| Endpoint / action | Purpose |
|---|---|
| `POST /api/register` | Public registration. Creates a pending account and returns a generic confirmation, with no `Set-Cookie`. |
| `POST /api/admin/users`, action `approve` | Sets `pending=false`, `enabled=true`, keeps password/rules/email, audits `registration_approved`. |
| `POST /api/admin/users`, action `reject` | Removes the record, audits `registration_rejected`. A user who is not pending cannot be rejected. |
| `POST /api/admin/settings`, action `registration_enabled` | Admin toggle; takes `{"enabled": true}` or `{"enabled": false}`. |
| `GET /api/status` | The unauthenticated response exposes only the `registration_enabled` boolean, not the other firewall settings. |

Registration is JSON-only, same-origin (the `Origin` header must match the
portal host when present) and IPv4-only. It is captcha-gated with the same
mechanism as login: Turnstile when configured, otherwise the proof-of-work
challenge from `/api/challenge`. It has a dedicated rate limit of 3 requests
per 10 minutes per source IP, separate from the login rate limit.

The request accepts either spelling for the main fields: `user` or `name`, and
`pass` or `password`. The `captcha` field is a JSON object in the same format
as `/api/login` (a solved proof-of-work payload or a Turnstile token).

##### Request example

```json
{
  "user": "alice",
  "pass": "correct horse battery staple",
  "email": "alice@example.com",
  "captcha": {"challenge": "...", "salt": "...", "algorithm": "SHA-256",
              "difficulty": 20, "expires": 1760000000, "signature": "...",
              "number": 123456}
}
```

##### Response examples

Success is a generic confirmation that does not reveal whether a username or
email was already present. The message text below is illustrative.

```json
{"ok": true, "message": "Your request has been recorded. After admin approval you can log in."}
```

| Situation | HTTP | Response |
|---|---|---|
| Registration disabled | `403` | `{"ok": false, "error": "...", "code": "registration_disabled"}` |
| Username already exists | `409` | `{"ok": false, "error": "...", "code": "username_taken"}` |
| Captcha failure | `403` | `{"ok": false, "error": "Captcha: ..."}` |
| Rate limit exceeded | `429` | `{"ok": false, "error": "..."}` |
| Invalid email | `400` | `{"ok": false, "error": "..."}` |

Email handling: the address is trimmed, lowercased, limited to 254 characters
and checked with a basic `name@domain.tld` pattern. Duplicate email addresses
are allowed on purpose. This avoids revealing whether an address is already
registered; email is only a contact record, not an identity or recovery
mechanism.

Audit behavior: `registration_requested` contains the username only, never the
email or password. Approval and rejection write `registration_approved` and
`registration_rejected`. A request is not an authentication event.

#### Settings

The flag is stored as `registration_enabled` (boolean, default `false`) in
`firewall-settings.json` in the state volume, validated by
`settings_store.validate_state` with the other settings. If the file is
invalid, the fail-closed fallback applies and registration stays off.

The admin Settings API changes it with:

```json
{"action": "registration_enabled", "enabled": true}
```

This action is portal-only: it is validated and committed to
`firewall-settings.json` without calling nftables or `apply_settings`. It does
not reload firewall rules and does not affect existing grants. The admin
**Settings** tab shows the option as the **Fiókkérelmek** checkbox; the login
page shows the **Fiók kérése** button only while the flag is enabled.

#### Admin UI

The **Admin → Users** tab has a separate pending section for accounts created
through the public form. A pending row shows the login name and the stored
email, with **approve** and **reject** actions.

- **Approve** activates the account: `pending=false`, `enabled=true`. The
  password, the empty rule list and the email are kept; the action is audited
  as `registration_approved`.
- **Reject** deletes the record and audits `registration_rejected`.

Approval does **not** grant rules or group memberships. The account is a
normal, enabled `user` with no rules; the admin assigns them later. Pending
accounts never count as admins, so the last-active-admin guard is unaffected.

#### Security notes

- No email is sent. The address is stored only; there is no verification
  message, delivery attempt or recovery flow. Email and passwords are never
  included in audit entries or logs.
- No session or cookie exists before approval. Pending accounts cannot log in,
  authorize access, receive rules or hold group memberships.
- Pending parsing is fail-closed: a missing flag is inactive (`false`), but a
  malformed value is treated as pending (`true`).
- `users.json` is written atomically with mode `0600` in the state volume.
  Email addresses are sensitive personal data; protect the volume and every
  backup that contains it.
- Duplicate emails are accepted to avoid confirming whether an address is
  already on file. Usernames must still be unique, so a duplicate username is
  reported as `username_taken`.
- Captcha and the dedicated rate limit apply before an account is created.
  Registration does not weaken TOTP 2FA, fail2ban, MAC binding or the
  two-phase access flow.
- Approval does not grant network access by itself. The user must still sign
  in, choose a rule and TTL, and authorize the grant; grants remain bound to
  the client IP and MAC address.

#### Limitations and future ideas

- **No email verification, delivery or notification.** The address is not
  verified and cannot be used for password recovery; new requests appear only
  in the Users tab pending section.
- **No invitation or allowlist flow.** While the toggle is on, any IPv4 client
  that can reach the portal and solve the captcha can request an account.
- **No cancellation, expiry or bulk operations.** Pending records stay until
  an admin approves or rejects them, one at a time.

<a id="totp-2fa"></a>

### 3.2 TOTP two-factor authentication

_Source: `docs/totp-2fa.md` (original title: „TOTP two-factor authentication”)._

**Date:** 2026-10-20

**Status:** implemented and committed as `c88b912`, deployed to the test VM
on 2026-10-20. QR-code enrollment is included in that commit and deployed.

This document is the technical reference for the optional per-user TOTP 2FA
in the portal. It describes the behavior, state, API surface and limitations.
It does not contain secrets, ticket values or recovery codes.

#### Behavior

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

#### Data model

User records live in `users.json` in the `dropjak-state` volume
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

#### API endpoints

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

#### Ticket semantics

- A ticket is created only after the password and captcha succeed for a user
  who needs a second factor.
- Tickets are held in memory only. A raw ticket is never written to
  `users.json`, `fail2ban.json`, the audit log or any other state file, and
  tickets are lost on server restart. The audit log records the ticket
  lifecycle (issued, rejected, expired, locked) with a non-reversible
  12-character SHA-256 hash (`ticket_hash`) and metadata such as purpose,
  attempt count and TTL; the ticket value itself is never recorded.
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

#### fail2ban integration

Wrong TOTP codes and wrong recovery codes count toward the same per-IP login
failure counter as wrong passwords. They use the existing fail2ban threshold,
window and ban duration. A banned IP is handled by the existing ban screen and
cannot sign in until the ban expires or is lifted. The ban state, drop log
and audit log never contain a ticket value, a TOTP secret or a recovery code.
For a pending ticket the audit log stores only its non-reversible 12-character
hash and lifecycle metadata (issued/rejected/expired/locked).

#### Configuration

The **Admin → Settings → Firewall name** value takes precedence: it sets the
issuer and label used in the `otpauth://` URI for new enrollments. When no
site name is configured, `HV_TOTP_ISSUER` (default `Dropjak`) is the
fallback. The variable is passed through `docker-compose.yml` as
`HV_TOTP_ISSUER: ${HV_TOTP_ISSUER:-Dropjak}` and documented in
`.env.example`. Existing authenticator entries keep their old issuer;
re-enroll to pick up a new name. The issuer changes only the label shown by
the authenticator app; it is not a security control. The 300-second ticket
TTL and the 5-attempt limit are fixed in this MVP.

#### Admin reset and CLI

The admin UI action **2FA reset** is the preferred path while the portal is
running: it clears the enrollment, revokes the user's in-memory sessions and
records the audit event.

If the admin UI is unavailable, reset from the host:

```bash
docker compose exec dropjak python3 /opt/hatarvedelem/server.py \
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

#### Security and limitations

- **Plain HTTP.** The portal has no HTTPS listener. The base32 secret and
  `otpauth://` URI are transmitted and displayed in cleartext, the QR code
  encodes the same secret, and the 6-digit and recovery codes are sent in
  request bodies. Anyone able to sniff the LAN can capture and replay them.
  `HV_COOKIE_SECURE=1` protects only the cookie; it does not encrypt the page
  or API bodies. Restrict `HV_PORTAL_NET` to a trusted network. Integrated
  HTTPS termination is a follow-up, not part of the current implementation;
  the plan is in [4.1 Domain proxy plan](#caddy-proxy-terv).
- **Seeds at rest.** TOTP seeds are stored unencrypted in `users.json` (mode
  `0600`) inside the state volume. Protect the volume and any backups; a
  backup contains the seeds and the recovery-code hashes.
- **No secrets in logs or audit.** The portal never writes TOTP secrets,
  ticket values or recovery codes to any log. Audit entries describe the
  action (for example `admin_totp_reset`) and, for a pending ticket, contain a
  non-reversible 12-character hash plus lifecycle metadata
  (issued/rejected/expired/locked), never the ticket itself. See
  [3.6 Audit log](#audit-naplo).
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

<a id="host-szabalyok"></a>

### 3.3 Host (input) rules

_Source: `docs/host-rules.md` (original title: „Host (input) szabályok”)._

Dropjak's rules are **forward**-oriented by default: the gateway forwards the
client's traffic toward the internet or a container published by Docker. The
portal host's **own** services (for example an `mpwerks` game server on port
25566) are not made reachable by forward rules, because those open traffic
passing through the host, not traffic directed at the host. This is what the
**host** (`input`) direction is for.

#### Creation

1. **Admin → Rules → New rule**.
2. In the **Direction** field, select **Input (host)**.
3. Enter the required TCP and/or UDP ports, for example TCP 25566.
4. Set the default and maximum duration, then save.
5. Assign the rule to the user or group, and on the login page the client
   selects it for access.

Example for the `mpwerks` server:

```
ID:          mpwerks-host
Name:        mpwerks (host)
Direction:   Input (host)
TCP ports:   25566
UDP ports:   25566   (if the service also uses UDP)
```

A host rule is selectable on the login page just like any other rule; in the
list it is distinguished by the **Host** marker.

#### Operation

- The portal puts the signed-in client's **IP address** into the
  `allowed_input_tcp` / `allowed_input_udp` nftables set, with the session
  TTL. No other client can reach the service.
- On the LAN the usual **MAC binding** also applies: the source IP alone is
  not enough. From the WAN the rule opens to the client's IP, without MAC
  binding.
- **fail2ban** bans and the anti-MAC-spoofing drop rules run **before** the
  host accept rule, so a banned client cannot reach the service even with the
  host rule.
- On logout, expiry or administrative revocation the portal removes the set
  elements. Existing connections are not closed only by the conntrack flush:
  the portal adds every host port that has ever appeared in a rule to the
  `host_service_tcp` / `host_service_udp` kernel-side set (it only adds, it
  never deletes during runtime). The input chain compares the destination
  port of established client→host packets against these, and drops the
  traffic if the source IP is no longer in the `allowed_input_tcp` /
  `allowed_input_udp` set. The host DNS (53) and DHCP existing accept rules
  run before the guard, so forward DNS and address renewal are not broken.
  Thus the connection is broken even if the conntrack flush is missed (crash,
  missing conntrack), or if the kernel (`nf_conntrack_tcp_loose`) recreates
  the flow from the next ACK. If the portal crashes, the kernel-side timeout
  still expires.
- The host rule works both from the LAN and from the WAN: the accept rule has
  no `iifname` condition, so it is also valid from the WAN if the source IP
  belongs to an authorized portal session. The portal removes any host allow
  for TCP 80 from the portal redirect.

#### SSH to the host

The first start without an admin account interrupts the current SSH session;
if the `breakglass` chain is unavailable, the provider console is the
recovery path.

Host SSH has a single path: a host rule created by an admin opens TCP port 22
with an `(IP, 22)` pair declared in the `allowed_input_tcp` set. An active,
authorized portal session from the same IP address is required, and an
existing SSH flow also stays alive only as long as this path is valid. UDP 22
is an ordinary host port, not SSH. The `admin` service established in
`services.json` means outbound (client-side) SSH in the forward direction; it
is not the portal host's host SSH.

Loading the first rule set can interrupt the currently running SSH connection
if there is not yet a host rule allowing TCP 22 assigned to the signing-in
admin. Before the first start, create the admin account, assign the host SSH
rule to it, and keep the provider (out-of-band) console open. If that is not
possible, the container can be started with `HV_SKIP_FIREWALL=1`, and after
creating the rule and the assignment it can be restarted with firewall
loading.

Every container restart empties the dynamic sets, so host SSH also closes:
the client must sign in again and authorize the host rule. The expiry of the
kernel-side timeout, logout and administrative revocation likewise delete the
`(IP, 22)` element immediately.

#### Limitations

- Only **explicit TCP/UDP ports** can be specified. Full access, ICMP and the
  old service list cannot be used in a host rule.
- Only **port 8100 (portal)** is reserved: neither the portal validation nor
  the kernel host accept allows it to be opened. **TCP port 22 (SSH)** can be
  opened with an admin-created host rule; UDP 22 is an ordinary host port, not
  SSH. A custom full-access rule still does not open SSH. The SSH path
  requires an active, authorized portal session from the same IP address.
- The service must listen on the portal host's **0.0.0.0** (or on the
  external interface), not only on `127.0.0.1`. Also check the host's own
  firewall: Dropjak only manages the `inet hatarvedelem` table.
- The same applies to collection rules: members may be forward or host
  (`input`) oriented; each member is granted in its own direction. The host
  part of a mixed collection goes into the `allowed_input_*` sets and is
  protected by the `host_service_*` guard set just like a standalone host
  rule. The port limits above apply to host members (no full access/ICMP,
  only 8100 reserved). The collection can open TCP port 22 only through an
  input-direction member that explicitly lists TCP 22; a full-access member
  is still not possible.

#### Quick test

On the portal host, start a temporary listener:

```bash
nc -l 25566
```

(With some `netcat` variants the correct form is `nc -l -p 25566`.) Then from
an authorized client:

```bash
nc <portal-host-ip-address> 25566
```

If the connection is established, the host rule works. If not, check whether
the client's session is active, whether the service is listening on the right
interface, and whether the host's own firewall is not dropping the packet.

#### Installation

Host rules require the new sets and rules in `deploy/dropjak.nft`. After
updating the template the container must be rebuilt/restarted; the dynamic
sets are emptied, so every client must sign in again. Before a production
deployment, ensure an independent administrative access path (console), and
do not remove the host rule that provides the existing SSH access.

<a id="gyujtoszabalyok"></a>

### 3.4 Collection rules and rule duplication

_Source: `docs/rule-collections.md` (original title: „Gyűjtőszabályok és szabályduplikálás”)._

In Dropjak's admin interface, two additional operations are available next to
the rules:

- **Duplicate** – copy any rule (standalone or collection) with one click;
  the reserved, legacy identifier is the exception.
- **Collection rule** – merge several existing standalone rules into a single
  selectable access rule.

A collection rule can be assigned to a user or group just like any other rule,
and appears on the login page as a single access option.

#### Semantics

A collection rule does not store its own ports and **has no direction of its
own** either. Its TCP, UDP and ICMP entitlements are the **union** of its
members' entitlements:

- TCP ports: the union of the members' TCP ports.
- UDP ports: the union of the members' UDP ports.
- ICMP: allowed if any member allows it.
- Full access: a collection can never grant full access, and a full-access
  rule cannot be a member.
- Direction (`direction`): each member is granted in **its own direction**.
  Forward members' ports go into the forward sets, host (`input`) members'
  ports go into the `allowed_input_*` sets. A collection's members may
  therefore be of mixed direction; the resolved collection's display
  direction is then `mixed` (a display/audit value only; the firewall
  operations work per direction with separate `Ports` sections). A member's
  direction can still be changed even when it is already a member of a
  collection; the dependent collections' sessions are then revoked.

A collection has its own `default_ttl` and `max_ttl`; the duration chosen at
login conforms to these, not to the members' TTLs. The resolved port list
appears everywhere in the interface in the usual `ports_label` field; for
collections the `collection: true` and the `members` list also appear.

Collection is one level deep:

- 1–64 different, existing **standalone** rules may be members;
- a collection may not contain another collection, itself, the reserved
  legacy identifier or a full-access rule;
- members are resolved at evaluation time; on a circular or missing
  reference the collection grants no access (fail closed), and the invalid
  entry is logged and skipped at load time.

#### Domain rule

The domain rule (`domains` list) opens the entries of the Caddy-based
subdomain proxy (Admin → **Domains**) by name. It has no direction, ports,
ICMP or full access, and never touches nftables: its `grants` list is empty,
so there is no kernel element at grant time or revocation time either. It may
only reference an existing proxy entry (checked at save time); while the
reference exists, the entry cannot be deleted or renamed. It can be a
collection member: the resolved collection's `domains` field is the union of
the members' domains. It can be selected only by explicit assignment (a
legacy account without assignment does not inherit it), and neither full
access nor the admin role substitutes for it.

```json
{
  "label": "OWUI",
  "description": "",
  "domains": ["owui"],
  "default_ttl": 3600,
  "max_ttl": 86400,
  "created": 1792500000
}
```

The payload is the same alongside `action`/`id`; `tcp`, `udp`, `icmp` and
`full` cannot be given with a value. In the interface `ports_label` shows the
full hostnames (`Domain: owui.z1.example.com`).

#### Service rule

The service rule (`service_refs` list) opens the tunnel services on the
**Proxy and tunnels** page, using
`"<agent-id>/<service-id>"` references. Like the domain rule, it has no
direction, ports, ICMP or full access; the ports are provided by the
referenced services' listening ports, in the forward direction. A port with
the `both` protocol (combined TCP+UDP) goes into both sets. The ports are not
persisted values: at save time and at decision time they are resolved from
the current mappings, so changing a mapping does not leave a stale grant.

- It may reference 1–64 different, existing and enabled services; a disabled
  agent or service cannot be selected.
- It cannot be combined with the `tcp`, `udp`, `icmp`, `full`, `members` or
  `domains` fields.
- It can be a member of a collection rule; the resolved collection inherits
  the union of the members' service references and ports.
- **Disabling** a service or agent is **always allowed**, even if a rule
  references it: access ceases in a fail-closed manner, and the sessions of
  the referencing rules (for an indirect collection member, the collections)
  are revoked immediately. **Deletion** is still rejected while a rule
  references it; the error lists the referencing rules.
- After changing the mapping or enabled state of the referenced service, the
  system recalculates the grants of the rule and dependent collections, and
  revokes the affected sessions. On re-enabling, the resolved ports are
  restored, but a session does not come back to life.
- At authorization the system re-checks the references and the resolved
  ports; on a missing or disabled reference, or a differing port set, the
  rule grants no access (fail-closed).
- The backward-compatible fallback for legacy accounts without assignment
  does **not** inherit service rules; those can be selected only by explicit
  assignment, just like domain rules.

```json
{
  "label": "Minecraft",
  "description": "",
  "service_refs": ["home/mc"],
  "default_ttl": 3600,
  "max_ttl": 86400,
  "created": 1792500000
}
```

The payload is the same alongside `action`/`id`. The response's `service_refs`
field contains the references, and the `services` list contains the resolved
labels, ports and the hostname of a domain-mode service: `[{ref, label, tcp,
udp, domain}]`. In the interface and the session view `ports_label` shows the
form `Service: <label> (TCP …, UDP …)`, and for a domain-mode service
`Service: <label> (<domain>)`.

#### Storage (`rules.json`)

Storage of standalone rules: `label`, `description`, `tcp`, `udp`, `icmp`,
`full`, `direction`, `default_ttl`, `max_ttl`, `created`. A missing
`direction` value is `forward` at load time.

A collection rule entry contains only these:

```json
{
  "label": "Web + DNS",
  "description": "Két egyedi szabály együtt",
  "members": ["web-only", "dns-only"],
  "default_ttl": 300,
  "max_ttl": 3600,
  "created": 1792500000
}
```

The `tcp`, `udp`, `icmp`, `full` and `direction` fields are deliberately
absent: ports and direction are computed values and are not persisted. Thus a
later change to a member does not leave behind a stale union or direction. At
load time the collection is recognized from the presence of the `members`
field, the references are checked, and invalid collections are logged and
skipped like other invalid rules. A `direction` field left over in an older
file is ignored at load time.

A service rule entry:

```json
{
  "label": "Minecraft",
  "description": "",
  "service_refs": ["home/mc"],
  "default_ttl": 300,
  "max_ttl": 3600,
  "created": 1792500000
}
```

Here too `tcp`, `udp`, `icmp`, `full`, `direction`, `members` and `domains`
are deliberately absent: the ports are values computed from the referenced
services' mappings, not persisted. At load time the service rule is recognized
from the `service_refs` field; a missing or disabled reference does not
discard the rule but yields empty resolved ports (fail-closed).

#### API

The admin endpoint remains `POST /api/admin/rules`. The response is the full
admin state (`_admin_state()`), and on a successful duplication additionally
`"message": "Rule duplicated."`.

##### Creating or modifying a standalone rule

```json
{
  "action": "create",
  "id": "web-only",
  "label": "Csak web",
  "description": "",
  "collection": false,
  "direction": "forward",
  "tcp": [80, 443],
  "udp": [443],
  "icmp": false,
  "full": false,
  "default_ttl": 300,
  "max_ttl": 3600
}
```

##### Creating or modifying a collection rule

```json
{
  "action": "create",
  "id": "web-dns",
  "label": "Web + DNS",
  "description": "",
  "collection": true,
  "members": ["web-only", "dns-only"],
  "default_ttl": 300,
  "max_ttl": 3600
}
```

A collection rule payload does not contain a `direction` field (if one
arrives anyway, the system ignores it; the members' directions decide).
Collection mode also turns on if the `collection` field is missing but the
`members` list is non-empty. For a collection, the `tcp`, `udp`, `icmp` and
`full` fields cannot be given with a value. For a standalone rule, alongside
`collection: false` the usual port fields and `direction` are valid; the
`members` field is ignored by the system if empty.

On editing, a rule can switch between standalone and collection mode, and the
`created` timestamp is retained. If a standalone rule is a member of any
collection, it must first be removed from the collections before it can
itself be turned into a collection or full access; this prevents two-level
collection from arising and keeps the collection's union from becoming
invalid.

##### Creating or modifying a service rule

```json
{
  "action": "create",
  "id": "mc-tunnel",
  "label": "Minecraft",
  "description": "",
  "collection": false,
  "service_refs": ["home/mc"],
  "default_ttl": 300,
  "max_ttl": 3600
}
```

Alongside `service_refs`, `tcp`, `udp`, `icmp`, `full`, `members` or `domains`
cannot be given; the service rule itself cannot be a collection (at most a
member of one). The references must exist, and the service/agent must be
enabled. If the resolved ports are empty in both protocols, the save is
rejected with 400.

##### Direct assignment (`users`, `groups`)

The create and update payload may optionally also accept a `users` and
`groups` list, for every rule type. The server interprets this as the rule's
**exact direct assignment set**: it sets the `users.rules` and `groups.rules`
lists separately, with an atomic file write, to this set, removing missing
elements and adding new ones. It does not modify group membership
(`groups.members`); group inheritance remains unchanged. The audit records the
change with the `users_added`, `users_removed`, `groups_added` and
`groups_removed` fields. For an invalid (unknown or pending) user or an
unknown group, the request is rejected with 400, and the rule is not
created/modified either. If the second of the two store writes fails, the
first modification is rolled back; the rule save remains in that case, and
the error indicates this.

##### Duplication

```json
{
  "action": "duplicate",
  "id": "web-only",
  "label": "Web only — copy",
  "new_id": "web-only-copy"
}
```

- `id` is required; `label` and `new_id` are optional.
- Without a new identifier, the system derives a unique one from the source
  identifier: `web-only-copy`, then on collision `web-only-2`, `web-only-3`,
  … The generated identifier is at most 32 characters and matches the
  rule-identifier format.
- Default name: `<source name> (copy)`; the interface sends a localized copy
  suffix (HU "másolat", DE "Kopie").
- The copy takes over the description, the TTLs, and for a standalone rule
  the ports/ICMP/full access, and for a collection the member list. For a
  collection, the resolved ports are **not** written into the copy's stored
  fields.
- The reserved legacy identifier cannot be duplicated; the operation does not
  touch nftables, and by itself grants access to no one.

##### Errors

Errors arrive with HTTP 400 and an English `error` text, for example:

- `members: a list of 1–64 rule identifiers is required`
- `members: at least 1 and at most 64 unique rules are required`
- `members: duplicate rule identifier`
- `unknown rule in the collection rule: …`
- `a collection rule cannot contain another collection rule: …`
- `a collection rule cannot contain a full-access rule: …`
- `service_refs: a list of 1–64 service references is required`
- `service_refs: duplicate service reference`
- `unknown or disabled service: …`
- `a service rule cannot have tcp, udp, icmp, full, members, domains`
- `the selected services have no available port or domain`
- `tunnel: the service cannot be deleted because a rule references it; …`
- `rule … is a member of the following collection rules: …; first remove it from the members`

#### Revoking sessions

If a standalone rule is modified and it is a member of one or more
collections, the system revokes, in addition to the rule's own selections,
the affected collections' selections as well, because the collection's port
union may have changed. From a session using several simultaneous accesses,
only the selection belonging to the modified rule and the dependent
collections disappears; the other selections remain with their original
expiry. If no selection remains, the session ends. The admin log's
`admin_rule_updated` event contains the `collections_affected` list and the
`sessions_revoked` count. Modifying or deleting a collection itself revokes
the collection's selection.

For a service rule, changing the mapping or enabled state of the referenced
service (redirecting the target host or target port, or disabling the
service/agent) recalculates, via the `reflect_services()` path, the resolved
ports and mapping signature of the direct rule and the dependent collections,
then revokes the selections of the changed rules. Before **deletion** the
system rejects the operation with the list of referencing rules; **disabling**,
by contrast, always goes through (fail-closed), and the referencing rules'
access ceases.

At the next status update the portal carries over the fresh rule list. The
revoked selection disappears from the selection, the interface indicates that
the affected access must be authorized again, and the modified definition
enters the firewall only with this new, explicit authorization. An already
running connection may be interrupted at the moment of revocation.

#### Deletion

- Deleting a collection deletes only the collection; the members remain
  untouched.
- A member cannot be deleted while any collection contains it. The error
  lists the collections' identifiers; the member must first be removed from
  the collections.
- A tunnel service or agent cannot be deleted while a service rule
  (directly or through a collection member) references it. The error lists
  the referencing rules. Disabling is not deletion: it is allowed even
  alongside a reference, and it revokes the referencing rules' sessions
  (fail-closed).

#### Limitations

- Collection is only one level deep; nested collections cannot be created.
- A collection's ports are unions, not intersections; members remain
  selectable individually too, if they are assigned to the user.
- A collection cannot grant full access, and a full-access rule cannot be a
  member.
- A collection has no direction of its own, and the interface does not offer
  a direction selector in collection mode. Members may be forward or host
  (`input`) oriented; each member is granted in its own direction, and the
  host rules' port limits (no full access/ICMP, only 8100 reserved) apply to
  host members. The collection can open port 22 only through an input-
  direction member that explicitly lists 22. A full-access member is still
  rejected; the full-access identifier from releases before 3.0.0 is
  reserved, cannot be created and cannot be a member. Details:
  [3.3 Host (input) rules](#host-szabalyok).
- Host SSH is opened exclusively by an admin-created host rule that
  explicitly contains TCP port 22 (directly or through a collection member),
  with an active, authorized portal session. A custom full-access rule and a
  full-access collection member do not.
- A service rule grants only forward ports, may reference 1–64 enabled tunnel
  services, and can be a collection member; the resolved collection's port
  union also includes the service ports. The fallback of a legacy account
  without assignment does not inherit.
- Duplication does not automatically assign the new rule to a user or group.
- Creating a collection and a duplicated rule does not directly modify the
  firewall; access is granted only by the usual login/authorization flow.

<a id="propagacios-matrix"></a>

### 3.5 Propagation matrix

_Source: `docs/propagation-matrix.md` (original title: „Propagációs mátrix”)._

This document describes how every administrative change takes effect on
already signed-in users, the kernel firewall, conntrack and the portal's
session store: which code performs the revocation, which nft elements
disappear, whether a conntrack flush is needed, and when the user must
authorize again.

The referenced line numbers refer to the state of the working tree on
2026-10-21. The audit findings F1–F9 and F11, and deviations N1–N3 and N5 are
fixed; F10 is accepted by a product decision (port 8100 is literally reserved,
not a bug), and N4 has only an availability residue left on the `shutdown()`
path. Multiple simultaneous access (section 8) is implemented. Notations:
`PASS`; `PASS WITH CAVEAT (<finding>)`; `GAP (<finding>)`.

Subsection 3.6 describes the propagation of the service rules introduced in
3.24.0, the multi-port tunnel mappings and direct rule assignment; the S1–S6
rows of the table refer to this version.

#### 1. Invariants

1. **Fail-closed forward.** The `forward` chain is `policy drop`; only a
   packet matching the dynamic sets and marked with `meta mark` may pass
   (`deploy/dropjak.nft:172`, `:245-250`); Docker's `DOCKER-USER` chain
   otherwise drops (`docker/entrypoint.sh:180-239`).
2. **The password alone never grants access.** A successful login creates
   only an `authorized=False` session (`gateway.py:6211-6285`); permission is
   placed into the kernel exclusively by the `grant_all()` call of
   `SessionManager.authorize()` invoked by `/api/access`
   (`gateway.py:6351`, `:6542`; `server.py:2470`).
3. **Permission is created at the moment of authorize, and deleted at the
   commit point of every semantics-changing modification.** The rule store
   returns the dependent collections within the same lock as the
   modification, at the commit point (`RuleStore.update_with_dependents()`,
   `gateway.py:2211-2227`); the server then immediately revokes the affected
   selections (`server.py:3356`). The commit and the revocation are not
   atomic, so in the event of a crash the TTL is the safety net; a revocation
   failure is not lost but goes into the bounded retry queue (F1).
4. **Revocation is coordinated with the locking of session state.** Every
   removal path calls the firewall under `SessionManager._lock`:
   `logout()` (`gateway.py:6592-6612`), `terminate()` (`:6613-6630`),
   `revoke_user()` (`:6631-6663`), `revoke_user_rules()` (`:6664-6682`),
   `revoke_rule()` (`:6683-6703`), `revoke_rules()` (`:6704-6727`),
   `revoke_ip()` (`:6728-6766`), `reap_once()` (`:6767-6812`),
   `validate()` (`:6286-6350`) and `_retry_pending_revocations()`
   (`:6059-6207`). On partial revocation `_subtract_grants()` subtracts the
   elements required by the remaining, active sessions, and in that case it
   does not flush conntrack either (`:5818-5886`, `:5887-5929`). Residual:
   `shutdown()` (`:6837-6855`) calls the firewall after removing the session,
   without the lock; this is only an availability residue (the session has
   already ceased, and the unlock-revocation may delete the ports of a new
   session authorizing in the meantime), not a security gap.
5. **A modified rule, collection, group or user never patches the existing
   permission.** The code does not rewrite the grant in the kernel: it either
   revokes it or leaves it untouched. When a rule is modified, its own and
   the dependent collections' selections are removed from sessions; if no
   selection remains, the session ends (`server.py:3356`). When a group is
   modified, the complete sessions of the old and new members cease
   (`server.py:3261`). Re-authorization is needed only if the session has no
   selection left; the remaining selections are reissued by the system with
   their original expiry.
6. **Kernel TTL is only a safety net.** Every element placed into a timeout
   set is placed with an explicit `timeout` (`gateway.py:3106`, `:3213`,
   `:3249`, `:3272`). The session's `expires` value and the grant TTL are the
   same; if the portal dies, the kernel deletes the element at the TTL. At
   expiry the portal also deletes separately: the reaper revokes the expired
   session's grants (including the `client_mac` element, `revoke_all()`
   `:3372-3373`), and fail2ban filters expired bans out of its memory as well
   (`fail2ban.py:1107-1113`, `:478-479`). The TTL does not replace
   revocation: a permit valid until expiry is itself valid, so revocation
   before expiry is mandatory.
7. **`host_service_tcp` and `host_service_udp` are an add-only guard set, not
   a grant.** They contain only the host ports ever declared; `sync_host_ports()`
   never deletes from them, and the startup flush also skips them
   (`deploy/dropjak.nft:80-94`, `gateway.py:3399-3441`, `:3716`). Their
   size is 65536, so all at most 65535 valid ports fit, and no guard element
   can silently be lost. The only deleting path is
   `prune_host_service_ports()`, which removes only a port that no persisted
   rule references and to which no live conntrack entry belongs; if nft
   listing or conntrack is unavailable, it deletes nothing
   (`gateway.py:3632-3715`, `:7129-7157`). The actual host permission is in the
   `allowed_input_tcp`/`allowed_input_udp` set, with a TTL. The guard set only
   cuts established traffic if the permission disappears.
8. **Bans and blocks take effect before every permission.** The `banned_v4`
   drop runs before the grants in the forward and input chains
   (`nft:204-205`, `:326-327`). The admin block jump is unconditional in the
   forward (`nft:229`) and input (`nft:337`) chains; the block uses the
   pre-DNAT destination port (`ct original proto-dst`) and the conntrack
   original tuple (`gateway.py:2765-2785`), so it also covers the reply
   direction and packets arriving from the WAN/Docker. The
   `block_nat`/`preauth_nat` jump is LAN-only (`nft:465-466`), because the
   pre-NAT section is relevant only for LAN traffic. F4 is fixed.
9. **One IP belongs to one session at a time.** A new login from the same IP
   first revokes the old permissions, then replaces the session
   (`gateway.py:6211-6285`); if the revocation fails, the old session is also
   dropped and the new login is not created either (fail-closed).
10. **The session store is in-memory.** Sessions are not persisted; on
    shutdown `shutdown()` revokes every permission
    (`gateway.py:6837-6855`, `Gateway.stop()` `:7574`). At startup there is no
    session reconciliation: everyone must sign in again. The startup
    flush/reconciliation and the behavior of the unsafe stale opt-in are
    described in section 5.
11. **Multiple rules in one session.** The session stores the selected rules
    in the `rules` and `rule_parts` fields (`gateway.py:5398-5399`);
    `rule`/`rule_label` is only the compatibility view of the first
    selection. The actual permission is the per-direction union of the
    selections (`union_grants()`, `gateway.py:445-497`): `full` in the same
    direction absorbs the TCP/UDP/ICMP parts, overlapping ports appear once,
    empty directions are omitted. The admin listing receives
    `selected_rules`, `selected_rule_labels` and per-direction `grants` fields
    (`gateway.py:5433-5460`).
12. **One session TTL, according to the strictest rule.** `authorize()`
    takes the smallest of the selected rules' `max_ttl` values as the upper
    bound; a request that is too long is an `AccessError`, not a truncation
    (`gateway.py:6398-6413`). A session has a single `expires` value.
13. **Partial revocation affects only the departing selection.**
    `_remove_selections_locked()` deletes the given rule identifiers from the
    session's `rule_parts` list; if a selection remains, the original expiry
    is unchanged, `revoke_exact` deletes the exact elements of the departing
    union, `grant_all()` reissues the remaining union (because an earlier
    `full` grant may have masked the port elements), and conntrack is targeted
    only at the departing ports (`gateway.py:5930-6057`). An expired session
    gets nothing back: it is removed entirely (`:5978-5988`). If no selection
    remains, the session ends.
14. **Fail-closed on multiple authorization and partial revocation.** The
    HTTP layer resolves every selected identifier before `authorize()`
    (`server.py:2586-2592`), so an invalid identifier does not leave a partial
    grant. On any firewall error the session is dropped, the old union is
    revoked (queued to the dependent line if necessary), and HTTP 503 is
    returned (`gateway.py:6495-6535`; `server.py:2599-2612`). A partial removal
    failure similarly closes by dropping the entire session and revoking the
    old union (`gateway.py:6035-6056`).

#### 2. Discovering the affected sessions

- **Direct match:** `rule_id in session.rules`, or for the legacy single-rule
  form `session.rule == <rule-id>`; the selection details are in
  `session.rule_parts` (`Session`, `gateway.py:5371-5399`), populated only
  for an authorized session (`:6567-6585`). `revoke_rule()` uses this
  (`:6683-6703`), and with multiple selections deletes only the given rule;
  `revoke_rules()` removes several identifiers under one lock, in one pass
  (`:6704-6727`).
- **Dependent collections:** `RuleStore.update_with_dependents()` returns
  the identifiers of the dependent collections within the same lock as the
  modification, at the commit point (`gateway.py:2211-2227`), so a collection
  created in the meantime cannot be left out either. The server revokes the
  rule and the dependents with a single `revoke_rules((rule.id, *dependents))`
  call (`server.py:3345-3357`); only the affected selections disappear from
  the session, the other selections' grants remain. Adding/removing a
  collection member affects only the sessions of those selecting the
  collection; the member's own selections remain untouched.
- **Group assignment:** the affected set is the union of the old and new
  members (`affected = set(existing.members) | set(updated.members)`,
  `server.py:3261`), and on deletion the group's members (`:3274`). Rules
  assigned to the group take effect through the `effective_for()` view
  (`gateway.py:1896`), so a relevant change to the group tears down the
  complete sessions of the members (`revoke_user()`).
- **User identity:** the session's `user` field; `revoke_user()` revokes
  every session (optionally except one) and their grants
  (`gateway.py:6631-6663`).
- **One-IP-one-session and replacement:** `login()` revokes the old
  permissions belonging to the same IP under the lock, then replaces the
  session with a `session_replaced` event (`gateway.py:6211-6285`);
  `revoke_ip()` also deletes grants in the dependent line as belonging to the
  IP, and under the lock discovers orphaned host/forward elements with
  `discover=True` (`gateway.py:6728-6766`).

#### 3. Main matrix

The columns are the same in every table; "Re-authorization" indicates whether
the two-phase authorization must be gone through again after the operation.

##### 3.1. Rules and collections

| Operation | Affected session and discovery | nft element/set | conntrack | Portal/audit | Re-authorization | Status |
|---|---|---|---|---|---|---|
| M1. Create standalone rule | None: the new rule is not assigned to anyone | None; optionally `host_service_*` sync | None | `admin_rule_created`; `sync_host_ports()` (`server.py:3343`) | No | PASS |
| M2. Duplication | None: the copy is not assigned | None; `sync_host_ports()` | None | `admin_rule_duplicated` | No | PASS |
| M3. Modify standalone rule | `session.rules`/`rule_parts` contains the id, plus the sessions of the dependent collections (`update_with_dependents`, `gateway.py:2211-2227`; `revoke_rules`, `:6704-6727`). Only the affected selection is deleted (`_remove_selections_locked`, `:5930-6057`), the other selections remain | The exact elements of the departing selection (`revoke_exact`); reissue of the remaining union with `grant_all()` if a departing `full` had masked it until now | Targeted `conntrack_flush_removed()`; full IP flush only if nothing remains authorized (`gateway.py:4052-4184`, `:6049-6055`) | `admin_rule_updated` (`collections_affected`, `sessions_revoked`); `sync_host_ports()` | Only if the session has no selection left | PASS |
| M4. Modify collection (ports/members/TTL) | `session.rules`/`rule_parts` contains the collection's id (`gateway.py:6683-6703`); only the collection's selection is deleted, the other selections remain | The exact elements of the collection's selection; reissue of the remaining union | Targeted; full IP flush only with an empty remainder | `admin_rule_updated`; `sync_host_ports()` | Only if no selection remains | PASS |
| M5. Add/remove a collection member | Only the sessions selecting the collection; the member's own sessions do not. Only the collection's selection disappears from the session, its other selections remain | The exact elements of the collection's selection; the member's grants are untouched | Targeted at the collection's departing ports | `admin_rule_updated`, `collections_affected` | Only if no selection remains | PASS |
| M6. Delete standalone rule | Non-collection-member only; deleting a collection member is `RuleStoreError` (`gateway.py:2309-2330`). `session.rules`/`rule_parts` contains the id; the user/group assignments are deleted. Only the affected selection is deleted (`revoke_rule`, `:6683-6703`) | The exact elements of the rule's selection; `host_service_*` deliberately remains | Targeted; full IP flush only with an empty remainder | `admin_rule_deleted` (`users_changed`, `groups_changed`, `sessions_revoked`) | Only if no selection remains | PASS |
| M7. Delete collection | `session.rules`/`rule_parts` contains the collection's id; the members' selections are untouched. Only the collection's selection is deleted | The exact elements of the collection's selection | Targeted; full IP flush only with an empty remainder | `admin_rule_deleted` | Only if no selection remains | PASS |

##### 3.2. Groups

| Operation | Affected session and discovery | nft element/set | conntrack | Portal/audit | Re-authorization | Status |
|---|---|---|---|---|---|---|
| M8. Create group | None | None | None | `admin_group_created` | No | PASS |
| M9. Modify group (rules, members, name) | All sessions of the old ∪ new members (`server.py:3167-3169`) | The members' grants, per direction | Yes, per member IP | `admin_group_updated` (`sessions_revoked`) | Yes | PASS |
| M10. Delete group | The members of the deleted group (`server.py:3184`) | The members' grants | Yes | `admin_group_deleted` | Yes | PASS |

Modifying a rule assigned to a group is not a separate operation: writing the
group's `rules` list is the M9 row, and performs the same revocation.

##### 3.3. Users

| Operation | Affected session and discovery | nft element/set | conntrack | Portal/audit | Re-authorization | Status |
|---|---|---|---|---|---|---|
| M11. Create user | None; new account | None | None | `admin_user_created` | No | PASS |
| M12. Approval | None: the pending account cannot even sign in (`server.py:1721-1734`) | None | None | `registration_approved` | No, until the next login | PASS |
| M13. Rejection | Pending account: no live session; the remaining group memberships and tickets are deleted (`server.py:2894-2896`) | None | None | `registration_rejected` (`sessions_revoked`, `tickets_revoked`) | No | PASS |
| M14. Admin user modification (role, enabled, rules, groups, password, metadata, must_change, totp_required) | `revoke_user(name)`: every session, before the modifications (`server.py:2958-2962`); on error the password is restored (`:2984-2991`) | All of the user's grants | Yes | `admin_user_updated` (`sessions_revoked`, `tickets_revoked` on disabling) | Yes | PASS |
| M15. Own password change | Every other session; except the current one (`server.py:2717-2719`) | The other sessions' grants | Yes | `password_changed` | Yes on the other devices | PASS |
| M16. Delete user (HTTP) | `revoke_user(name)`; deletion of group membership and 2FA tickets (`server.py:3080-3083`) | The user's grants | Yes | `admin_user_deleted` | No, the account ceased | PASS |
| M17. 2FA reset (HTTP) | After `reset_totp()`: `revoke_user()` and tickets (`server.py:3048-3049`) | The user's grants | Yes | `admin_totp_reset` | Yes | PASS |
| M18. CLI `user add` / `passwd` | On the daemon over the control channel (`server.py:4580-4589`, `:4607-4614`); local write only if there is no live daemon (`_control_mutation`, `:4420-4468`). The daemon also tears down existing sessions with the same name (`:3700-3701`, `:3725-3730`) | Via the daemon path, revocation of the grants; in local mode there is no daemon and no live session | Via the daemon path yes; in local mode there is no live session | `cli_user_created` / `cli_password_changed` | Via the daemon path yes; in local mode there is no live session | PASS |
| M19. CLI `user del` | On the daemon (`server.py:3744-3776`), with deletion of group membership (`:3762`) and revocation (`:3763-3764`); in local mode the group cleanup also happens (`:4633-4636`) | Via the daemon path the grants; in local mode there is no live session | Via the daemon path yes; in local mode no | `cli_user_deleted` | Via the daemon path yes; in local mode no | PASS |
| M20. CLI `user totp-reset` | On the daemon (`server.py:3778-3810`, revocation `:3796-3797`); local mode only without a live daemon | Via the daemon path the grants; in local mode there is no live session | Via the daemon path yes; in local mode no | `cli_totp_reset` | Via the daemon path yes; in local mode no | PASS |

##### 3.4. fail2ban

| Operation | Affected session and discovery | nft element/set | conntrack | Portal/audit | Re-authorization | Status |
|---|---|---|---|---|---|---|
| M21. Manual ban (HTTP) | `_on_fail2ban_ban` → `sessions.revoke_ip(ip)` (`gateway.py:6727-6728`) | `banned_v4` element with explicit timeout; the kernel drops the grants before the ban anyway | Yes | `fail2ban_ban`; drop-log event | Yes, after the ban expires | PASS |
| M22. Manual unban / unban all (HTTP) | No revocation; the ban ceasing does not restore an old grant | Deletion of the `banned_v4` element (`unban`, `gateway.py:3202-3206`; `unban_all`) | Not needed | `admin_fail2ban_changed` | The old grant is not restored; re-authorization needed | PASS |
| M23. Automatic login ban | `on_ban` → `revoke_ip` (`gateway.py:6727-6728`) | `banned_v4` with timeout | Yes | `fail2ban_ban`; `login_failed` | Yes | PASS |
| M24. Automatic drop ban | `_on_drop` → `record_drop` → `on_ban` → `revoke_ip` (`gateway.py:6675`, `:6727-6728`) | `banned_v4` with timeout | Yes | `fail2ban_ban` | Yes | PASS |
| M25. CLI `fail2ban ban/unban/unban-all` | On the daemon, over the control channel it calls the running `Fail2ban` instance (`server.py:4759-4768`), so the ban is `on_ban` → `revoke_ip` (`:3826-3831`); a local instance only if there is no live daemon (`:4412-4468`) | `banned_v4` write/delete; via the daemon path also grant and conntrack revocation | Via the daemon path yes; in local mode there is no live session | `fail2ban_ban` / `fail2ban_unban`, `cli_*` | Via the daemon path yes; in local mode there is no live session | PASS |
| M26. Threshold, counter and time-window settings | No direct session effect; the three signals can be toggled separately: failed logins (`enabled`), dropped packets (`drop_count_enabled`) and distinct destination ports (`drop_ports_enabled`). Disabling logins releases only the `source != "drop"` automatic bans, disabling both drop counters together releases only the `source == "drop"` bans; manual bans always remain (`fail2ban.py:1075-1210`). Thresholds cannot be 0: a `drop_max`/`drop_ports` value of 0 is rejected by `validate_config`, and a saved legacy 0 is migrated at load (the counter turns off, the threshold is set to the default). A disabled counter does not count, does not store an event and does not ban; turning off its own switch does not affect existing bans. | `banned_v4` release; on error the configuration is unchanged, and the released bans are restored with their exact remaining time | No | `admin_fail2ban_changed`, `fail2ban_bans_released`; on error `fail2ban_bans_release_failed` | No | PASS WITH CAVEAT (F9 residual: the orphan line and the rollback are best-effort) |
| M27. Ban-list eviction (MAX_BANS) | No direct session effect | Both the memory record and the kernel element of the oldest entry are deleted; on error a bounded orphan line and retry (`fail2ban.py:844-878`, `:309-352`) | No | `fail2ban_ban_evicted` (`kernel_released`), `fail2ban_ban_evict_failed` | No | PASS WITH CAVEAT (F9 residual: the orphan line is best-effort) |

##### 3.5. Settings and lifecycle

| Operation | Affected session and discovery | nft element/set | conntrack | Portal/audit | Re-authorization | Status |
|---|---|---|---|---|---|---|
| M28. Create, modify, delete, toggle pre-auth / block setting | No session revocation: the block runs before every grant, the pre-auth is not a grant | Replacement of the `preauth`, `block`, `preauth_nat`, `block_nat` chains in a single transaction (`replace_custom()`, `gateway.py:2845-2871`); on an invalid settings file the pre-auth is emptied and the block's last known good content is retained (`:6904-6923`, `:6948-6957`) | Not needed: the block matches the conntrack original tuple | `admin_settings_changed`; on error 503 and rollback (`:6959-6999`) | No; the block is effective immediately | PASS |
| M29. Enable registration / site name | None | None | None | `admin_settings_changed` | No | PASS |
| M30. Admin session termination | One `sid` (`terminate()`, `gateway.py:6613-6630`) | The given session's grants | Yes | `admin_session_terminated`; one's own session cannot be terminated | Yes | PASS |
| M31. Logout | The current session (`logout()`, `gateway.py:6592-6612`) | The session's grants | Yes | `session_ended` / `access_revoked` | Yes | PASS |
| M32. Natural expiry | The reaper deletes the expired session (`gateway.py:6767-6812`) | The expired grants; the kernel TTL deletes independently of this too | Yes | `session_expired` | Yes | PASS |
| M33. New login from the same IP | The old session and its grants; on error both are dropped (`gateway.py:6211-6285`) | The old grants | Yes | `session_replaced`, `access_revoked` | Yes | PASS |
| M34. Re-authorization to another rule/rules | The difference between the old and the new union (`_subtract_grants`, `gateway.py:5818-5886`); exact revocation of the departing elements (`:6506-6535`), on error the session ends and there is no new grant; on success issuance of the new union (`:6542`) | Departing elements with `revoke_exact`, new union with `timeout` | Targeted `conntrack_flush_removed()`; full IP flush only with an empty remainder (`:6563-6566`) | `access_granted` / `access_modified` (`rules`, `rule_labels`, `rule_count`, `removed_rules`); on error `firewall_error` (503) | Only after an error | PASS |
| M35. Startup, restart, crash | No persisted session; see section 5 | Flush or reconciliation of the dynamic sets; stale only with explicit opt-in | No global flush at startup | `service_start` / `service_stop` | Yes | PASS WITH CAVEAT (after a crash the old grants may live until the TTL) |
| M36. `.env` change (TTL, interfaces, PORT) | Running sessions remain untouched; see section 5.3 | Re-rendering and loading the template requires a restart | Not automatic | No automatic event | Yes, after restart | PASS (F10 product decision: the reserved port is always the literal 8100) |

##### 3.6. Service rules, tunnel mappings and direct assignment

| Operation | Affected session and discovery | nft element/set | conntrack | Portal/audit | Re-authorization | Status |
|---|---|---|---|---|---|---|
| S1. Create or modify a service rule | None: at rule creation it is not selected yet; on modification the same as M3 (the rule's and its dependent collections' selections are deleted) | Forward ports resolved from the service's `mappings`; for a domain-mode service there are no ports, the grant is empty, the session is for the domain (`session_domains`); `host_service_*` is not affected (the service is forward-oriented) | Only the targeted flush according to M3 | `admin_rule_created` / `admin_rule_updated` (`service_refs`); the existence and enabled state of the references are checked before saving; without a port and domain the save returns an error | Only if no selection remains | PASS |
| S2. Modify a tunnel service's mappings (listen/target/proto/enabled, target host/target port) | `service_references()` finds the referencing service rules through collections too; `reflect_services()` refreshes the rules' resolved `service_tcp`/`service_udp` ports and non-persisted mapping signature, then the server tears down the sessions selecting the affected rules with `revoke_rules()` (`server.py:4044-4057`) | The exact elements of the departing selection; the modified mapping's new ports enter only on a new authorization | Targeted, at the departing ports | `admin_settings_changed` (`service_rules_refreshed`, `sessions_revoked`); on an error before saving the setting is unchanged | Yes, if the session has no other selection left | PASS |
| S3. Delete or disable a tunnel service | On disabling, `service_references()` finds the referencing service rules through collections too; `reflect_services()` refreshes the resolved ports/signature, then `revoke_rules()` tears down the affected sessions. On deletion there is no revocation, because the operation goes through only if no rule references it (`_tunnel_reference_error`); otherwise `SettingsError` | The exact elements of the departing selection | Targeted, at the departing ports/sessions | `admin_settings_changed` (`sessions_revoked`); on deletion, on error there is no event | Yes, if the session has no other selection left | PASS (disabling is fail-closed) |
| S4. Delete or disable a tunnel agent | On disabling, the same as S3 for all of the agent's service references: `reflect_services()` + the union of the referencing rules' identifiers + `revoke_rules()`. On deletion the operation goes through only without a reference (`server.py` `_tunnel_reference_error`/`_tunnel_domain_reference_error`) | The exact elements of the departing selection | Targeted, at the departing sessions | `admin_settings_changed` (`sessions_revoked`); on deletion, on error 503 and unchanged setting | Yes, if the session has no other selection left | PASS |
| S5. Direct assignment (`users`, `groups` on the rule API) | No immediate revocation: the assignment only changes the candidate list of a later `/api/access`, it does not affect a grant already given. Group membership is unchanged | None | None | `admin_rule_created` / `admin_rule_updated` (`users_added`, `users_removed`, `groups_added`, `groups_removed`) | No; it takes effect at the next authorization | PASS WITH CAVEAT (removing the assignment does not tear down an already running session; it lives until the TTL or the next revocation) |
| S6. Missing or disabled referenced service at the moment of authorization | Authorization re-resolves the `service_refs` list with `_rule_available()`, and compares it with the `service_tcp`/`service_udp` ports stored in the rule, as well as with the non-persisted `service_signature` containing the complete effective mapping; on a difference (including target host/target port redirection), a missing or disabled reference, the rule cannot be selected and the request is an `AccessError` (fail-closed). The legacy bare-`rules`-list fallback does not give an automatic grant for a service rule. The running session is torn down by the mapping change (S2), not by this check | No new element | None | `access_denied` / `firewall_error`; the error does not leave a partial grant | Yes | PASS |

A domain-mode service as a service rule: the save goes through without a port
if at least one referenced service is domain-mode; `session_domains` is the
union of the explicit `domains` and the resolved service domains. On the nft
side there is no new element in this case (the `grants` is empty), and access
takes effect at the domain proxy gate. Alongside the mapping change according
to S2, renaming the domain also counts as a change, because the signature
also contains the `("domain", …)` line; disabling is fail-closed according to
S3/S6, and `_rule_available()` also checks the match of `session_domains`.
The collection inherits the domain of the domain-mode member as well, without
adding a port.

#### 4. Sets and TTLs

Every element placed into a timeout set is placed with an explicit `timeout`:
`_bind_mac_locked()` (`gateway.py:3054-3057`), `grant_all()` (`:3178-3183`),
`ban()` (`:3197-3200`) and `sync_bans()` (`:3214-3220`). The `host_service_*`
sets are not timeout sets; the normal sync only adds (`:3313-3353`), and
`flush()` skips them (`:3633-3636`).

| Set | Type and size | Timeout | Writer | Deleter | Element TTL | Early removal | After expiry |
|---|---|---|---|---|---|---|---|
| `allowed_v4` | `ipv4_addr`, 4096 | `flags timeout` | `grant_all()` for full access | `revoke_all()` always, `deny()`, `flush()` | explicit `timeout {ttl}s` | revocation, ban, block, expiry | kernel deletes; forward drop |
| `allowed_tcp` | `ipv4_addr . inet_service`, 16384 | timeout | `grant_all()` forward TCP | `revoke_all()` (grant or `discover`), `deny()`, `flush()` | explicit | revocation, expiry | kernel deletes; drop |
| `allowed_udp` | `ipv4_addr . inet_service`, 16384 | timeout | `grant_all()` forward UDP | `revoke_all()`, `deny()`, `flush()` | explicit | revocation, expiry | kernel deletes; drop |
| `allowed_input_tcp` | `ipv4_addr . inet_service`, 16384 | timeout | `grant_all()` input TCP | `revoke_all()` always filtered to IP, `flush()` | explicit | revocation, expiry | kernel deletes; the input established guard closes |
| `allowed_input_udp` | `ipv4_addr . inet_service`, 16384 | timeout | `grant_all()` input UDP | `revoke_all()` always filtered to IP, `flush()` | explicit | revocation, expiry | kernel deletes; the input established guard closes |
| `allowed_icmp` | `ipv4_addr`, 4096 | timeout | `grant_all()` for ICMP | `revoke_all()` always, `flush()` | explicit | revocation, expiry | kernel deletes; drop |
| `client_mac` | `ipv4_addr . ether_addr`, 4096 | timeout | `_bind_mac_locked()` from `grant_all()`, only on the LAN | `_unbind_mac_locked()` (`:3061-3070`), `revoke_all()` (`:3309-3310`), `flush()` | explicit | revocation, MAC binding ceasing, expiry | kernel deletes; the MAC-drop rule runs only on the LAN |
| `banned_v4` | `ipv4_addr`, 4096 | timeout | `ban()` (`:3197-3200`), `sync_bans()` (`:3214-3220`) | `unban()` (`:3202-3206`), `unban_all()`, `flush()` | explicit; `sync()` gives the remaining time truncated to whole seconds, at least 1 s | unban, expiry | kernel deletes; the ban ceases |
| `host_service_tcp` | `inet_service`, 65536 | none | `sync_host_ports()` only adds (`:3313-3353`) | only `prune_host_service_ports()` (`:3546-3628`), without a reference and live conntrack; `flush()` skips it | none | prune, only under the two conditions | persists forever; only tightens, does not grant |
| `host_service_udp` | `inet_service`, 65536 | none | `sync_host_ports()` only adds (`:3313-3353`) | only `prune_host_service_ports()` (`:3546-3628`), without a reference and live conntrack; `flush()` skips it | none | prune, only under the two conditions | persists forever; only tightens, does not grant |

`sync()` passes the remaining time as `int(until - now)`, `max(1, ...)` is
only a lower bound; expired records are skipped (`fail2ban.py:1058-1100`).
`sync_bans()` writes the received TTL into the kernel as `max(1, int(ttl))`
(`gateway.py:3220`); this does not extend the ban. Expired bans are also
deleted from memory by `snapshot()` (`fail2ban.py:1107-1113`), and at load
time they are dropped by `_parse_record()` (`:478-479`).

When a session expires, the reaper revokes the grants under the lock; if no
active session remains for the IP, `revoke_all()` also deletes the
`client_mac` element (`gateway.py:3372-3373`), and in the partial case
`_subtract_grants()` deletes only the non-overlapping elements
(`:5818-5886`): a departing `full` may be omitted only if an active `full` of
the same direction exists, while non-`full` departing parts are returned for
exact deletion even alongside an active `full`, so that they cannot resurface
later. The `host_service_*` prune runs only after a successful sync, and its
failure does not harm the health of the guard set (`:6651-6666`); if nft
listing or conntrack is unavailable, no port is deleted.

#### 5. Startup, restart, crash

##### 5.1. `HV_FLUSH_ON_START` and the related switches

| Situation | Entrypoint behavior | Gateway behavior | Result | Status |
|---|---|---|---|---|
| Not set, `1`, `true`, `yes`, `on` | `flush_on_start=1`; flushing of the dynamic sets except `host_service_*` (`docker/entrypoint.sh:28-41`, `:328-343`) | `_env_bool()` (`gateway.py:72-80`); `_startup_flush_mode()` `flush` (`:83-99`); `_startup_flush()` flushes (`:6773-6822`) | Clean start; every old grant disappears | PASS |
| `0`, `false`, `no`, `off` | The switch is off, but by default **reconciliation** happens: flushing of the dynamic sets (`entrypoint.sh:334-343`) | `_startup_flush_mode()` returns `reconcile` mode, and flushes (`gateway.py:95-99`, `:6815-6820`) | Orphaned grants do not remain | PASS |
| Invalid value | The default is `1` (`entrypoint.sh:28-41`) | The default is `True` (`gateway.py:72-80`) | Clean start | PASS |
| `0` and `HV_ALLOW_STALE_GRANTS_ON_START=1` | Explicit, unsafe opt-in: the flush is skipped (`entrypoint.sh:331-332`) | `stale_allowed`: the flush is skipped, loud log (`gateway.py:6790-6797`) | The old grants may stay alive until the kernel TTL, up to 30 days, without a session | PASS WITH CAVEAT (unsafe opt-in; N5 fixed) |
| Flush error | `die`, startup stops (`entrypoint.sh:340-341`) | On `FirewallError`: log, audit, exception; startup stops (`gateway.py:6800-6814`) | Fail-closed | PASS |
| Portal process crash | The container is `restart: unless-stopped` (`docker-compose.yml:15`); in native mode `Restart=on-failure` (`deploy/dropjak.service:39`) | Sessions are lost; the grants remain in the kernel until the TTL | Until restart the old grants are valid without a session | PASS WITH CAVEAT (TTL safety net) |
| Host restart | The kernel state is cleared; `dropjak-firewall.service` loads the template (`deploy/dropjak-firewall.service:18-21`) | The portal flushes at startup, then reloads fail2ban, the host ports and the settings | Clean state | PASS (runtime assumption: the units are enabled) |
| `HV_SKIP_FIREWALL=1` | Loading the template, the Docker guard and the watchdog are skipped (`entrypoint.sh:392-394`); `env_bool` accepts every true form | The portal's nft calls still run; if the table is missing, the operations fail with an error | No fail-closed guarantee if the table is not loaded | PASS WITH CAVEAT (developer/dangerous opt-in only; N3 fixed) |

`HV_FIREWALL_WATCHDOG` (compose `:123`; `entrypoint.sh:244`) turns the
firewall watchdog off/on; with `0` the watchdog does not run.
`HV_SKIP_FIREWALL` is likewise interpreted as `env_bool`
(`entrypoint.sh:392-394`), it does not accept only the exact `"1"`.

##### 5.2. What is reconciled at startup, and what is not

- **Flushes:** `allowed_v4`, `allowed_tcp`, `allowed_udp`, `allowed_input_tcp`,
  `allowed_input_udp`, `allowed_icmp`, `client_mac`, `banned_v4`
  (`entrypoint.sh:336-338`; `gateway.py:3630-3653`).
- **Does not flush:** `host_service_tcp`, `host_service_udp` (add-only) and
  the `breakglass` chain (`deploy/dropjak-firewall.service`).
- **Reloads:** `fail2ban.sync()` with the saved bans (`gateway.py:6876`,
  `fail2ban.py:1058-1100`); `sync_host_ports()` with the persisted input ports
  (`gateway.py:6854`, `:6576-6666`); `_apply_custom_settings()` with the
  pre-auth/block (`:6896-6946`).
- **Does not persist:** sessions, grants, conntrack. At startup there is no
  global conntrack flush; forward closes due to the set matching, and input is
  protected by the `host_service_*` guard. If `sync_host_ports()` fails,
  startup does not stop, it only logs and audits; new host permissions remain
  closed fail-closed with 503 until the next `authorize()`'s single retry
  succeeds (`gateway.py:5990-6006`, `:6561-6574`). An already existing host
  connection may stay alive through the general
  `ct state established,related accept` rule (`nft:418`) until the port enters
  the guard set; therefore the admin must resolve the sync failure as soon as
  possible.

##### 5.3. `.env` changes

The environment variables are read once at process import; modifying `.env`
does not affect the running process.

- **TTL:** `HV_SESSION_TTL`, `HV_MIN_TTL`, `HV_MAX_TTL`, `HV_AUTH_TTL`
  (`gateway.py:142-155`). The existing `expires` does not change; new logins
  and `authorize()` calls use the new value; the rule TTLs are in
  `rules.json`.
- **Interfaces:** `HV_LAN_IF`, `HV_WAN_IF`, `HV_LAN_NET`, `HV_PORTAL_NET`;
  the template is rendered by the entrypoint (`entrypoint.sh:119-169`), and
  MAC binding is decided at import (`gateway.py:244-260`). Switching takes
  effect only with a template reload and restart; the old grants are removed
  by the startup flush.
- **PORT:** goes into the `__PORT__` placeholder and the HTTP binding
  (`entrypoint.sh:124-125`, `:166-167`; `gateway.py:138`); changing it
  requires a restart and nft reload. **F10 product decision:** the reserved
  port, regardless of the `PORT` value, is always the literal 8100
  (`gateway.py:1272-1290`); the input accept also excludes 8100
  (`nft:444-445`). This is not a bug but an accepted design decision: 8100
  remains the only reserved port even if the portal listens on another port.
  Setting `PORT != 8100` is therefore not recommended.
- **Why a restart and flush are needed:** grants live only in the kernel; on
  restart the session store is emptied, but the kernel elements would remain
  until the TTL, so the startup flush is mandatory.
- **Compose whitelist:** `HV_ALLOW_STALE_GRANTS_ON_START` is carried over
  into compose (`docker-compose.yml:91-94`) and documented in `.env.example`
  (`:155-158`); `HV_FIREWALL_WATCHDOG` (`docker-compose.yml:123`;
  `.env.example:159`) and `HV_SKIP_FIREWALL` (`docker-compose.yml:124`;
  `.env.example:164`) are also available. In native systemd mode the unit
  does not read `.env`, the `Environment=` lines must be modified
  (`deploy/dropjak.service:16-36`). N5 fixed.

#### 6. Findings (F1–F11)

The status shows the initial defect and the final state as of 2026-10-20.
F1–F9 and F11 are `FIXED`; F10 is accepted by product decision, not a bug.

| ID | Severity | Status | One-line impact | Reference |
|---|---|---|---|---|
| F1 | High | FIXED | A failed revocation goes into a bounded (4096) queue, the cleaner thread retries it under the session lock with increasing delay; on partial revocation `_subtract_grants()` deletes only the elements not required by the remaining session, and discovery runs only without a session. | `gateway.py:5639-5733`, `:5818-5886`, `:5887-5929`, `:6059-6207`, `:6728-6766`; M3–M7, M9–M10, M14, M30–M33 |
| F2 | High | FIXED | Both the entrypoint and the gateway interpret `HV_FLUSH_ON_START` as `env_bool`; with `0`, a safe reconciliation happens by default, stale can remain only with an explicit opt-in, and a flush error stops startup. | `gateway.py:72-99`, `:6773-6822`; `docker/entrypoint.sh:28-41`, `:328-343`; M35 |
| F3 | Medium | FIXED | On re-authorization a failure to revoke the old grant drops the session, gives no new grant, and returns `FirewallError` (503); the error also enters the pending line. | `gateway.py:6506-6535`; M34 |
| F4 | Medium | FIXED | The block jump in the forward and input chains is unconditional, the block matches the conntrack original tuple (reply direction and WAN/DNAT too), and `block_nat` is LAN-only. | `nft:229`, `:337`, `:465-466`; `gateway.py:2765-2785`; M28 |
| F5 | Medium | FIXED | The size of `host_service_tcp/udp` is 65536, so it cannot fill up; the normal sync is add-only, and the safe prune deletes only a port without a reference and without live conntrack; if nft listing or conntrack is unavailable, it deletes nothing. | `nft:80-94`; `gateway.py:3313-3353`, `:3546-3628`, `:6654-6666`; section 5.2 |
| F6 | Medium | FIXED | CLI modifications go to the daemon over the control channel; there is no local fallback with an ambiguous reply or a live daemon, local write happens only without a live daemon. The daemon's `user del` also deletes group membership, and so does the local deletion. | `server.py:4420-4468`, `:4517-4694`, `:4697-4849`; `:3685-3847`; M18–M20, M25 |
| F7 | Medium-Low | FIXED | The ban is checked by the session check, the login and `/api/access` too; a banned IP cannot use its existing session either, and access also revokes it. | `server.py:529-537`, `:1661-1671`, `:2428-2448`; M23–M24 |
| F8 | Low | FIXED | Invalid `client_mac` JSON gives a `FirewallError` (not an empty list), and `_unbind_mac_locked()` deletes the existing/known MAC element even for a non-LAN address. | `gateway.py:2939-3000`, `:3061-3070`; section 4 |
| F9 | Low | FIXED | Ban-list eviction releases the kernel element of the evicted entry (on error it retries with a bounded, in-memory orphan line); `sync()` gives the exact remaining TTL; `configure()` restores with an unchanged configuration on error. Residual: the orphan line and the rollback remain best-effort. | `fail2ban.py:844-878`, `:309-352`, `:943-1055`, `:1058-1100`; `tests/test_fail2ban_consistency.py`; M26–M27 |
| F10 | Low | ACCEPTED BY DESIGN | By product decision the reserved port is always the literal 8100, regardless of the `PORT` value; both the host-port validation and the input accept use 8100. This is not a bug but a deliberate decision; `PORT != 8100` is therefore not recommended. | `gateway.py:138`, `:1272-1290`; `nft:444-445`; M36 |
| F11 | Low | FIXED | The replacement of the pre-auth/block chains happens in a single nft transaction (`replace_custom()`); there is no intermediate state without a block, and on an invalid settings file the pre-auth is emptied and the block's last known good content is retained. | `gateway.py:2845-2871`, `:6904-6923`, `:6948-6957`; M28 |

##### 6.1. Further deviations found during the review (not F1–F11)

- **N1 (Medium) — FIXED:** the admin user modification revokes the sessions
  before writing the password, metadata and group membership
  (`server.py:2958-2962`); if a later step fails after the password write, the
  password is restored (`:2984-2991`). Test:
  `test_admin_update_failure_revokes_and_restores_password`
  (`tests/test_gateway.py:6761`).
- **N2 (Medium) — FIXED:** CLI `user del` deletes group membership both on the
  daemon (`server.py:3762`) and in local (no-daemon) mode (`:4633-4636`), just
  like the HTTP deletion (`:3081`). Test:
  `test_cli_local_delete_removes_group_membership`
  (`tests/test_gateway.py:6836`).
- **N3 (Low) — FIXED:** `HV_SKIP_FIREWALL` uses `env_bool`
  (`docker/entrypoint.sh:392-394`), so it also accepts the `true`, `yes`, `on`
  forms.
- **N4 (Low) — FIXED, residual:** `logout()`, `terminate()`,
  `revoke_user()`, `revoke_user_rules()`, `revoke_rule()`, `revoke_rules()`,
  `revoke_ip()`, `reap_once()`, `validate()` and
  `_retry_pending_revocations()` call the firewall under the lock
  (`gateway.py:6592-6612`, `:6613-6630`, `:6631-6663`, `:6664-6682`,
  `:6683-6703`, `:6704-6727`, `:6728-6766`, `:6767-6812`, `:6286-6350`,
  `:6059-6207`). The expiry/IP-change revocation of `validate()` already runs
  under the same lock as the session deletion. Remainder: `shutdown()`
  (`:6837-6855`) calls the firewall after removing the session, without the
  lock; this is an availability residue, because a new session authorizing in
  the meantime with the same ports may have them deleted by the old
  revocation.
- **N5 (Low) — FIXED:** `HV_ALLOW_STALE_GRANTS_ON_START` entered the compose
  whitelist (`docker-compose.yml:91-94`) and `.env.example` documents it
  (`:155-158`); in compose it is available from `.env`.

#### 7. Tests and coverage

##### 7.1. Unit tests

- `tests/test_revocation.py` (29 tests): `PendingRevocationTests` (`:212`),
  `DiscoveryTests` (`:575`), `StartupFlushTests` (`:622`),
  `EntrypointFlushParsingTests` (`:722`), `EntrypointBooleanFlagsTests`
  (`:782`). Covers the revocation queue, partial grant subtraction,
  discovery, the startup decision matrix and the entrypoint's `env_bool`
  interpretation.
- `tests/test_revocation_lock_scope.py` (12 tests): `LockScopeTests` (`:151`),
  `PartialGrantTests` (`:195`), `FullRevokeTests` (`:257`),
  `RetryOutsideLockTests` (`:286`). Checks the lock scope, the expiry
  revocation of `validate()`, partial revocation and retry outside the lock.
- `tests/test_host_service_guard.py` (17 tests): `TemplateCapacityTests`
  (`:178`), `HostPortHealthTests` (`:199`), `HostServicePruneTests` (`:330`).
  Set size, fail-closed guard and safe prune.
- `tests/test_block_generation.py` (15 tests):
  `ApplyCustomBlockGenerationTests` (`:121`), `InvalidBlockEntryTests`
  (`:331`), `ClearCustomTests` (`:405`), `ReplaceCustomTests` (`:457`),
  `ApplyCustomSettingsTests` (`:565`). Block rendering, atomic
  `replace_custom`, block retention with an invalid setting.
- `tests/test_block_precedence.py` (8 tests):
  `BlockPrecedenceTemplateTests` (`:61`), `ApplyCustomBlockRuleTests`
  (`:246`). The unconditional block jump and precedence before the grants.
- `tests/test_fail2ban_consistency.py` (8 tests): `EvictionTests` (`:125`),
  `SyncTtlTests` (`:191`), `ConfigureAtomicityTests` (`:230`). Eviction/orphan
  line, sync TTL, configure rollback.
- `tests/test_live_cli.py` (40 tests): `ControlServerTests` (`:310`),
  `ControlPeerCredentialTests` (`:586`), `ControlStartupTests` (`:621`),
  `CliFallbackTests` (`:719`), `Fail2banRaceTests` (`:965`). The daemon's
  control channel, the prohibition of fallback with an ambiguous/live daemon,
  and the ban/login race.
- The tests of `tests/test_gateway.py` related to multiple access:
  `UnionGrantsTests` (`:2752`, 4 tests), `SubtractGrantsTests` (`:2793`,
  3 tests), `MultiSelectionTests` (`:2835`, 9 tests),
  `ConntrackFlushRemovedTests` (`:3223`, 4 tests), and the six multiple-access
  tests of `HttpTests` (`:3501`, 45 tests):
  `test_access_multi_rule_union`, `test_access_multi_rule_validation`,
  `test_access_multi_rule_modification_revokes_removed`,
  `test_access_legacy_single_rule_still_works`,
  `test_status_reports_multi_selection` and
  `test_admin_session_listing_shows_multi_selection`. Covers the union,
  overlapping ports, exact subtraction, conntrack direction handling, the
  strictest TTL, partial revoke, the prohibition of reissuing an expired
  session, the single-pass operation of `revoke_rules` and the HTTP contract.
- `tests/test_propagation_multi.py` (7 tests): `PropagationHttpTests`
  (`:1`) and the direct `SessionManager` tests. Covers the real user
  scenario: the collection is the **second** element of the selection; after
  editing the member only the collection's selection disappears, the other
  selections and the expiry remain; the member is in two collections but only
  one is selected; the collection and the member selected together disappear
  in one pass; re-authorization after the modification gives the new
  definition; the shared input 22 is not deleted and gets no conntrack flush;
  the mixed-direction collection cleans both exact sets. All 7 tests OK.
- The other mentioned classes of `tests/test_gateway.py`: `AdminHttpTests`
  (`:7026`, 50 tests), including
  `test_admin_update_failure_revokes_and_restores_password` (`:7604`) and
  `test_cli_local_delete_removes_group_membership` (`:7679`); furthermore
  `FirewallTests` (`:351`), `UserStoreTests` (`:1283`), `SessionTests`
  (`:2178`), `RuleGroupStoreTests` (`:5628`), `TotpCliTests` (`:9942`),
  `CliAuditTests` (`:10077`), `Fail2banTests` (`:12069`),
  `DropBanWiringTests` (`:12475`), and the entrypoint tests (`:11928`,
  `:11955`, `:11971`, `:11995`).

The full package on the final working tree: **563 tests, OK** (2026-10-21).

##### 7.2. Live VM tests

`tests/e2e_vm.py` contains the final, gated scenario matrix; the gates are in
lines `:64-68` (`HV_E2E_LONG`, `HV_E2E_PENDING`, `HV_E2E_RESTART`,
`HV_E2E_MULTI`).

- **K1. Revocation paths** (`scenario_revocation_matrix`, `:1345`): no
  separate gate; it runs if the admin API and the scenario resources are
  available (`:2739-2755`), otherwise skip (`:2765-2774`). Covers logout,
  admin terminate, rule, collection-member and group modification, user
  disabling/deletion and the fail2ban ban.
- **K2. Natural expiry** (`scenario_natural_expiry`, `:1499`):
  `HV_E2E_LONG` gate; when off, skip (`:1511`). Checks the expiry of the TTL
  and the disappearance of the grants.
- **K3. Block precedence** (`scenario_block_precedence`, `:1699`):
  `HV_E2E_PENDING` gate; when off, `pending_skip` (`:1702`).
- **K4. Restart matrix** (`scenario_restart_matrix`, `:2238`):
  `HV_E2E_RESTART` gate; when off, skip (`:2241`).
- **K5. CLI propagation** (`scenario_cli_propagation`, `:2027`):
  `HV_E2E_PENDING` gate; when off, `pending_skip` (`:2030`).
- **K6. Simultaneous authorization of multiple rules** (`scenario_multi_access`,
  `:2432`): `HV_E2E_MULTI` gate; when off, skip. The rule pair is given by
  `HV_E2E_RULES` (`:2143-2149`, default `e2e-rev-fwd,e2e-rev-host`). The
  scenario covers the multiple union, the partial selection and the targeted
  revocation.

The scenarios are implemented and gated, but there is no evidence in the
repository that they have run on the VM; finalization requires a live run.
**K6 has not yet run live.**

##### 7.3. Missing tests (TODO)

- A live VM, per-port conntrack fallback test (the prune's no-conntrack branch
  is covered at unit level).
- Running K1–K6 live on the VM and recording the results (K6 is meant to
  prove live the union of multiple selection, its partial revocation and its
  UI).

#### 8. Multiple simultaneous access (implemented)

**Data model.** `Session` stores the identifiers of the selected rules in the
`rules: tuple[str, ...>` field and the complete selections in the
`rule_parts: tuple[RuleSelection, ...]` field (`gateway.py:5398-5399`);
`rule`/`rule_label` remains the compatibility view of the first selection
(`:6567-6585`). A `RuleSelection` bundles the rule's identifier, label and
grants (`:432-443`). `selections()` produces the selection even from a legacy,
single-rule session (`:5414-5423`), and `snapshot()` also emits the
`selected_rules`, `selected_rule_labels` and per-direction `grants` fields
(`:5433-5460`). `Session.ports`/`ports.label()` remains a flattened, display
view.

**Union and TTL.** `union_grants()` merges the grants per direction
(forward/input) (`gateway.py:445-497`): the TCP/UDP ports as a set, in
ascending order; ICMP with an OR relation; `full` in the same direction
absorbs the TCP/UDP/ICMP parts; empty directions are omitted; the result is
deterministic (forward, then input). The session TTL cannot exceed the
smallest `max_ttl` of the selected rules; the request is rejected, not
truncated (`:6398-6413`).

**Authorization and re-authorization.** `authorize(token, ip, rules, ttl)`
accepts a single `Rule` (legacy callers) or a non-empty sequence
(`gateway.py:6351-6437`). It deduplicates the identifiers in order of first
occurrence, validates every rule, then deletes the elements departing between
the old and new union (`_subtract_grants`, `:5818-5886`) with `revoke_exact`,
and issues the new union with `grant_all()` (`:6496-6542`). Conntrack is
targeted only at the departing ports (`:6563-6566`). If the revocation of the
departing elements fails, the session ends, the old and the new union are
revoked, and HTTP 503 is returned; no new grant is created
(`:6506-6535`; `server.py:2599-2612`).

**Partial revocation.** `_remove_selections_locked()`
(`gateway.py:5930-6057`) deletes the given rule identifiers from the session's
`rule_parts` list. If a selection remains, the session keeps its original
expiry, `revoke_exact` deletes the exact elements of the departing union,
`grant_all()` reissues the remaining union (necessary because an earlier
`full` grant may have masked the port elements), and conntrack is targeted
only at the departing ports (`:6001-6055`). An expired session gets nothing
back: it is removed entirely (`:5978-5988`). If no selection remains, the
session ends. On a firewall error it is fail-closed: the session is dropped,
and the complete old union is revoked (`:6035-6056`).
`revoke_user_rules(user, rule_ids)` deletes only the given selections from a
user's sessions (`:6664-6682`); `revoke_rules(rule_ids)` removes the rule and
the dependent collections under one lock, in one pass (`:6704-6727`);
`revoke_rule(id)` remains for the other callers (`:6683-6703`).

**Exact subtraction.** `_subtract_grants()` omits the departing `full`
element only if an active `full` of the same direction covers it
(`gateway.py:5818-5886`). The non-`full` departing parts covered by an active
`full` are returned for exact deletion, otherwise the earlier
`allowed_tcp/udp/icmp` elements could resurface later.

**Conntrack.** `conntrack_flush_removed(ip, removed, remaining)`
(`gateway.py:4052-4184`) performs a full IP flush only if, alongside the
departing `full`, nothing remains authorized. With a remaining grant it never
performs a full flush; if any remaining part is `full`, it skips the targeted
commands (conntrack is direction-blind). It computes port/ICMP coverage from
the union of all remaining directions. With more than 16 targeted commands
and a remaining grant it logs and skips (`:4132-4141`); it falls back to a
full flush only with an empty remainder.

**HTTP and UI.** `POST /api/access` accepts the form
`{"rules": [identifiers...], "rule": first, "ttl": N}` (`server.py:2521-2536`).
`rules` is authoritative: a non-empty list containing only non-empty strings,
deduplicated, at most `MAX_SESSION_RULES = 16` (`server.py:63`, `:381-414`).
Every identifier is resolved before `authorize()`, so there is no partial
grant (`:2586-2592`). The legacy `{"rule": id, "ttl": N}` still works. The
authorization response and `/api/status` are extended with the
`selected_rules`, `selected_rule_labels`, `grants` fields, while the legacy
`rule`/`rule_label`/`grant` fields remain (`server.py:833-853`, `:958`). The
audit `access_granted`/`access_modified` event is extended with the `rules`,
`rule_labels`, `rule_count` fields, and on modification with `removed_rules`;
the `direction` may also be `mixed` (`server.py:2620-2652`). The portal UI
uses multiple selection, the union TTL limit and per-direction grant display;
the admin session list shows the labels of the selected rules. The K6 live
scenario (`tests/e2e_vm.py`, `HV_E2E_MULTI`, `HV_E2E_RULES`) is implemented
but has not yet run on the VM.

**Live interface refresh.** For an authorized session the browser refreshes
the `auth.rules` catalog from the 30-second `/api/status` poll, rather than
using the snapshot taken at login. In the modification (`access`) view,
`refreshAccessFromStatus()` stays in place: when the `rulesSignature()`
fingerprint changes, it redraws the rule cards, keeps a still-valid
in-progress selection, removes a modified or disappeared rule from the
selection, and if the server has revoked the selection, it prints that the
affected access must be authorized again. Before opening the **Modify** button
it requests a fresh `/api/status` (`cache: no-store`); on a network error it
uses the cached snapshot but does not navigate away. The session view
indicates a selection change detected in the poll with a
`sessionRevokedNotice` message, and keeps it on subsequent polls too. A rule
modification therefore shows up immediately in the interface as well, but
authorizing the new definition remains an explicit, two-phase operation.

**Residual limitations.** These are known and do not remove the guarantees
above:

1. `SessionManager._lock` is a single global lock held during the entire
   nft/conntrack call; a slow or stuck `nft` can block every session
   operation. The 16-command/3-second conntrack limit
   (`CONNTRACK_REMOVED_LIMIT`, `gateway.py:4049`, `:4132-4141`) mitigates but
   does not eliminate the risk.
2. With `direction="mixed"`, the legacy flattened `Session.ports` /
   `ports.label()` audit and snapshot label may display input ports as
   forward; enforcement and the `grants` are direction-correct, and the admin
   UI uses the `grants` field (`gateway.py:5425-5432`, `:5433-5460`).
3. `sync_host_ports()` leaves a narrow TOCTOU window for a newly added input
   port between the rule store commit and the invalidation of the guard set;
   this matters only if the subsequent sync and the conntrack cleanup also
   fail (`server.py:3345-3357`, `gateway.py:7129-7148`).
4. On test firewalls `revoke_exact` may fall back to
   `revoke_all(only_grants=True)`; the production `Firewall` always has
   `revoke_exact` (`gateway.py:5734-5746`, `:3377-3397`).

The M3–M7 and M34 rows of the matrix apply to the multiple-selection model;
"Re-authorization" is mandatory only if the session has no selection left (or
the revocation dropped it in a fail-closed manner).

#### 9. Unverified runtime assumptions

- An `nft -f` reload flushes the chains but not the sets, so dynamic elements
  in principle survive; we have not run this on the VM.
- `conntrack -D -s IP` deletes every entry with the source IP; the presence
  of the binary and the capability depends on the installation, and on error
  only an audit is produced (`gateway.py:3927-3958`).
- The behavior of the `DOCKER-USER` guard and the host namespace depends on
  the Docker version; the code relies on `meta mark` and the `DOCKER-USER`
  chain (`docker/entrypoint.sh:180-239`).
- The enabled state of the systemd units and the operation of
  `Restart=on-failure` have not been checked; the filling of the non-
  `host_service_*` sets (4096/16384) has not been tested live either. The
  65536 size of `host_service_*` is covered at unit level
  (`tests/test_host_service_guard.py`).
- The single global `SessionManager._lock` of multiple access is held during
  the entire nft/conntrack call; a slow or stuck `nft` can block every session
  operation. The 16-command/3-second conntrack limit
  (`CONNTRACK_REMOVED_LIMIT`, `gateway.py:4049`, `:4132-4141`) mitigates but
  does not eliminate the risk.
- With a `direction="mixed"` session, the legacy flattened `Session.ports` /
  `ports.label()` audit and snapshot label may display input ports as
  forward; enforcement and the `grants` are direction-correct, and the admin
  UI uses the `grants` field (`gateway.py:5425-5432`, `:5433-5460`).
- `sync_host_ports()` leaves a narrow TOCTOU window for a newly added input
  port between the rule store commit and the invalidation of the guard set;
  this matters only if the subsequent sync and the conntrack cleanup also
  fail (`server.py:3345-3357`, `gateway.py:7129-7148`).
- On test firewalls `revoke_exact` may fall back to
  `revoke_all(only_grants=True)`; the production `Firewall` always has
  `revoke_exact` (`gateway.py:5734-5746`, `:3377-3397`).
<a id="audit-naplo"></a>

### 3.6 Audit log

_Source: `docs/audit-log.md` (original title: "Audit log")._

The portal keeps a security audit log of sign-ins, second-factor events,
access changes, session lifecycle, fail2ban actions, admin operations and
command-line maintenance. The audit log complements the process log and the
drop log: it records **who did what, from where, and with what result**, not
packet payloads.

#### Location and format

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
supports `limit`, `event`, `events`, `user`, `q`, `before`, `severity` and
`ip` filters. The **Logs** admin tab exposes those filters, including a
**Szint** (severity) selector and an **IP-cím / CIDR** field.

A single `event=` keeps the old partial match (`event=admin_` finds the
whole `admin_*` family, display labels such as `Access Granted` work too).
`events=a,b` (repeatable, or several `event=` parameters) is an exact set:
an entry matches when its event code is one of the listed codes. Each code
must look like an event code (`[a-z][a-z0-9_]{0,63}`, at most 200 codes),
otherwise the reply is a 400; a well-formed but unknown code simply matches
nothing. The Logs tab sends its searchable multi-select as `events=`.

The `ip` filter takes a single IPv4/IPv6 address or a CIDR range
(`192.168.10.0/24`); anything else is a 400 with an error. It
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

#### Severity levels

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

#### Redaction guarantees

`AuditLog.write` applies the redaction rules centrally, so no call site can
accidentally persist a secret in a normal key:

- Exact keys `pass`, `password`, `password_hash`, `hash`, `secret`,
  `totp_secret`, `code`, `recovery`, `recovery_code`, `cookie`, `token`,
  `ticket` and `otpauth_uri` are **omitted** from the entry. The process log
  records only the field name (`[audit] sensitive field omitted: <key>`),
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

#### TOTP ticket lifecycle

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

#### Other event families

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

#### Audit of audit reads and failure handling

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

#### Rotation, retention and backup

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

<a id="motd"></a>

### 3.7 Post-login notice (MOTD)

The portal can show an optional notice after a successful sign-in, before the
user chooses an access rule. It is a portal-styled modal, not a browser alert.
The title and the close button are translated (HU **Fontos közlemény** /
**Bezárás**, EN **Important notice** / **Close**, DE **Wichtige Mitteilung** /
**Schließen**). The modal blocks the access screen until the single close
button (or Escape) is pressed; it does not close on a timer.

#### Validity

The text and the validity are stored in the existing settings file as
`motd_text` and `motd_expires_at`:

- Empty `motd_text` disables the feature; the text is stripped and limited to
  2000 characters.
- An empty `motd_expires_at` means permanent.
- A non-empty expiry must be an ISO-8601 datetime with a time zone. It is
  normalized to UTC (`YYYY-MM-DDTHH:MM:SSZ`) on save.
- A past expiry is accepted on save; it simply means the notice is already
  inactive.

The active notice is computed server-side (`settings_store.active_motd`). An
expired or disabled notice is never included in any response. It is sent only
to authenticated sessions: `/api/status` includes `"motd"` in the
authenticated payload, and the no-TOTP login response includes it alongside
the session cookie. Login, pending-account, banned and unauthenticated
responses do not contain it.

The client shows the notice only from `showAccess()`, guarded by a per-login
`motdShown` flag. The 30-second status poll (`refreshAccessFromStatus`) does
not re-open it. The flag is reset in `endSession()`, so the next sign-in shows
the then-current notice again.

#### Admin settings

**Admin → Settings → Napi közlemény (MOTD)** provides a multiline text field,
a **Állandó (nincs lejárat)** / permanent toggle and a **Érvényes eddig** /
valid-until datetime field that is disabled while permanent is checked. An
empty text clears the notice. Sending `action: "motd"` with a text but no
expiry while permanent is unchecked is rejected client-side; the server
validates the text length, type and datetime independently.

The `motd` action is display-only: unlike the pre-auth/block settings it does
not pass through nftables preparation or application. Saving writes the
settings file atomically. The audit entry `admin_settings_changed` records the
acting user, `target: "motd"`, the text length (`motd_length`) and the expiry,
but never the notice text itself. Invalid input returns HTTP 400 and leaves
the previous settings untouched.

<a id="alagut"></a>

### 3.8 Tunnel (Tunnels)

A tunnel connects the cloud-hosted Dropjak with a home Docker network behind
NAT without having to open any port at home. Its model is playit.gg: the cloud
receives the public traffic, and the WireGuard tunnel carries it as far as a
home agent container. The proxy and the tunnel are found on the same admin page
("Proxy és alagutak" — "Proxy and tunnels"); direct proxy entries need no agent,
the tunnel is only needed to reach one's own network behind NAT.

#### Topology

```
client ──► cloud Dropjak ( public port )
              │  DNAT → 10.77.0.2:<tunnel port = external port>
              │  SNAT → 10.77.0.1
              ▼
        dropjak0 (WireGuard, UDP)
              │  encrypted tunnel
              ▼
   home agent container (on the SINGLE Docker bridge network shared
   with the playit.gg agent, e.g. playitgg-net; container-name resolution
   on the built-in DNS)
       wg0 10.77.0.2 ──► DNAT → <container>:<target port>
              │  SNAT → the agent's address on the bridge
              ▼
   normal Docker bridge network (playitgg-net) ──► service container
```

The agent works the same way as the playit.gg agent: no separate internal
network is needed, the services do not have to be moved, and there is no manual
network configuration. The service stays on the single bridge network shared
with the playit.gg agent; in the cloud the target is the container's name and
port (e.g. `purpur:25565`). The agent reaches **only the containers on this
network**; another network, the host gateway and the host's Docker socket are
not reachable. The installer (whose output and comments are in English) offers
the host's bridge networks in a numbered list, and connects the agent to
exactly the selected one network; `playitgg-net` is the default if it exists.
In a non-interactive installation `DROPJAK_NETWORK=<network>` decides, and the
installer never connects to all networks.

#### Cloud side

- **Settings:** `tunnels` section in the settings file: `port` (WireGuard
  UDP, default 51820), `endpoint` (the cloud's public address; when empty the
  portal derives it from the request's address), server key pair, agent list.
- **Agent:** the UI allocates a `10.77.0.x` address and a one-time
  enrollment token; the agent generates its own keys (see "Enrollment"
  below). The address comes from the `10.77.0.2`–`10.77.0.254` range; the
  server is `10.77.0.1`.
- **Enrollment (DJ-08, DJ-25):** "New agent" stores the record with
  `public_key: null`, `enroll_token_hash` (SHA-256 of the token) and
  `enroll_expires` (now + 30 minutes). The plaintext token is in the
  add/re-enroll response only: the UI shows it once, keeps it in page memory
  and sends it as `X-Dropjak-Enroll-Token` when it downloads the installer
  or the JSON config (409 `enroll_token_required` / `enroll_expired` /
  `agent_enrolled` otherwise). The bundle (`agent.json` version 2) carries
  the server public key, the endpoint, the agent address, the sync URL and
  `enroll: {url, token}`; no private key, no PSK, no sync token. On first
  start the agent runs `wg genkey`/`wg pubkey`/`wg genpsk`, keeps the keys in
  `identity.json` (0600) in its `agent-state` volume and calls
  `POST /api/tunnel/enroll` on the portal's public address (an https
  `HV_PORTAL_URL`, the Caddy name the admin used, the proxy's portal
  domain or first root, then plain HTTP; never the tunnel) with
  `{agent_id, public_key, preshared_key}` and `Authorization: Bearer
  <enrollment token>`. The portal checks the hash in constant time, the
  expiry and single use (the hash is cleared), stores the public key and the
  PSK, configures the peer and returns a long-lived sync token once; only
  `sync_token_hash` is stored. The endpoint is rate-limited (10 per 5
  minutes per source IP), refuses tunnel peers (404), is part of
  `HV_WAN_HTTPS_ONLY`, answers every token problem with the same 403
  `enrollment refused`, and is audited (`tunnel_agent_enrolled`,
  `tunnel_enroll_failed` with a reason). Until it enrolls the agent has no
  peer; the card shows "waiting for enrollment" (or "enrollment expired").
- **Re-enroll and migration:** agents created before enrollment keep their
  gateway-generated `private_key`, `preshared_key` and plaintext `token`
  (the "legacy" shape) and keep working, and their installer can still be
  downloaded. **Re-enroll** (`tunnel_agent_reenroll`, in-page confirmation)
  deletes the stored private key, PSK, plaintext token, public key and sync
  token hash and issues a new enrollment token; the running agent
  disconnects until the new installer enrolls it. An enrolled agent's
  installer cannot be re-downloaded (its keys exist only on the agent);
  re-enroll instead. The settings validation accepts both shapes, never a
  mix.
- **Service:** per agent `{id, label, target_host, enabled,
  public, domain, mappings}`; the elements of the `mappings` list are
  `{proto, listen, target}`. `public` (by default `false`) denotes access
  without the portal, `domain` (by default empty) the HTTPS name behind Caddy.
  `listen` and `target` accept a port, a range and a list of these
  (`80,443`, `8000-8100`), and are paired by index; the two lists must have the
  same length. A service, agent and mapping may have at most 256 ports. In
  domain mode the mapping is a single TCP item, and the `listen` is the
  internal port allocated by the server.
- **No separate tunnel port:** in port mode the internal tunnel port always
  matches the external `listen` port; the old 41000–41999 allocator is gone.
  Only the domain service automatically receives an internal port from the
  41000–60999 range (see below). Ports 22, 2019, 53,
  67, 80, 443 and the portal's port 8100, as well as the
  WireGuard UDP port when an agent is active, still cannot be a listener port,
  even within a range.
- **Protocol merging:** TCP and UDP mappings arriving on the same
  listener/target port pair merge into `both`. The same listener port with a
  different target port or target host is rejected. The `(protocol, listener
  port)` pair is unique across all services and the direct port proxies;
  `both` reserves both protocols.
- **Agent protocol:** the sync response is still one entry per listener port
  (`id="p<port>"`, `proto`, `tunnel_port` = the listener port, `target` =
  `host:port`); the server expands the mappings. The old single-port service
  shape `listen_port` + `tunnel_port` + `target` is automatically migrated on
  load to the `mappings` shape; the old `tunnel_port` value is lost, because
  the listener port takes its place.
- **nft:** services are DNATed as synthetic forward entries in the
  `portproxy_nat` chain (`iifname "<WAN>"`, `fib daddr type local`), and
  `portproxy_snat` masquerades to the `10.77.0.1` address. The `tunnel_input`
  chain opens the WireGuard UDP port only when an agent is enabled, narrowed
  to the WAN interface, and allows the portal's sync endpoint from `dropjak0`
  (`10.77.0.0/24` → TCP 8100). Without an agent the chain is empty, the port
  closed.
- **Access:** the tunnel's public port is by default **bound to portal
  authorization just like** the port proxy. The forward chain's existing
  `ct original ip saddr . ct original proto-dst @allowed_tcp/udp` rule
  decides; the packet of a client without portal sign-in and rule selection is
  dropped (and counted by the drop-based fail2ban).
- **Public port service (`public: true`):** the port-mode service is reachable
  without portal sign-in. On every apply the server derives the WAN-only
  pre-auth accepts from the live settings: for every protocol of the port an
  `iifname "<WAN>" ct status dnat … meta mark set <fwd_mark> accept`, and a
  `ct state established … accept` rule is created. The LAN direction is
  deliberately not opened, and no targetless `related` rule is added (that
  would let all related traffic through). The `block` chain runs earlier in
  the base chain, so a block still overrides the public service. The synthetic
  rules disappear automatically when the service is disabled, deleted or
  becomes private; the user's pre-auth entries are not touched by the system.
- **Domain service (`domain != ""`):** the service does not get a WAN port but
  an HTTPS name behind Caddy. The domain can only be a lowercase, valid FQDN
  (at most 253 characters, 1–63 character labels, `a–z`, `0–9`, `-`, no
  wildcard/scheme/port), and a **strict** subdomain of a configured
  `proxy_domains` root (the longest matching root wins). It cannot be a root
  domain, the `portal_domain`, a `proxy_routes` host, and cannot match
  (case-insensitively) another tunnel service's domain. In domain mode there
  is exactly one mapping, `proto: "tcp"`, with a mandatory target host and a
  target port between 1 and 65535; the listener port is not chosen by the user.
  The internal (tunnel) port is allocated by the server deterministically as
  the smallest free port from the **41000–60999** range; the occupied ones
  include every explicit port-mode listener port, the WireGuard port,
  `PORT_PROXY_RESERVED_LISTEN` and the portal's port, as well as previously
  allocated internal ports. The allocated port is written into the mapping's
  `listen` field, and remains unchanged on revalidation; if there is no free
  port, the save is rejected with `SettingsError`. The domain service has no
  WAN DNAT and does not appear among the port-proxy entries; Caddy forwards to
  the `10.77.0.2:<internal port>` address via `/api/proxy/ask`/`auth`. It does
  not appear in the service-rule selector (it has no WAN port); its access is
  governed by a domain rule. With `public: true` it is reachable without a
  domain rule, with `public: false` only by a session that selects the domain.
  Deleting the domain service or the agent containing it, as well as changing
  or removing the domain, is rejected if a domain rule references the hostname
  (`rules.domain_references()`); the error message also gives the referenced
  name. Disabling the agent/service is allowed even alongside a reference
  (fail-closed).
- **Agent configuration unchanged:** the downloaded `agent.json` and the sync
  service dicts of `GET /api/tunnel/config` still contain only the
  `{id, label, proto, tunnel_port, target, enabled}` keys; the `domain`/`public`
  fields are exclusively server-side, so the strict agent schema remains
  backward compatible. The domain service also appears in the agent's sync
  with the allocated internal port, so that the agent can DNAT from `wg0` to
  the target container.
- **Sync:** `GET /api/tunnel/config`, `Authorization: Bearer <token>`.
  Only an enabled agent whose peer IP according to the raw socket matches
  exactly receives a response; the token comparison is constant-time
  (`hmac.compare_digest` of `sha256(bearer)` with `sync_token_hash`; a legacy
  agent's plaintext token until it is re-enrolled). A
  5-second rate limit per agent. The response contains only the given agent's
  service list (without key and token).
- **Status:** `wg show` handshake and traffic data; online if the handshake is
  fresher than 180 seconds. The `error` field shows if the WireGuard operation
  failed; this does not stop the portal.

#### Service reachability test

In the service row of the agent card the **Teszt** (Test) button
(`tunnel_service_test`) checks the whole path from the portal host to the
agent's DNAT, without touching the public WAN address and the loopback: the
server opens a TCP connection to the port of the agent's `10.77.0.x` address to
which both Caddy and the DNAT forward. The connection being established is
success; the cause of the failure is shown in English
(`timeout`, `refused`, `network error: …`). For `udp` and `both`
protocols a zero-byte UDP probe is also sent: no response is expected, so
silence is success; `ConnectionRefusedError` (ICMP unreachable) is failure. For
`both` TCP is authoritative, but the UDP probe also runs. A single call
examines at most four mappings in parallel, for at most six seconds in total;
the response is per mapping `{proto, listen, target, ok, detail}` and an
English summary line. The test is read-only: it writes no setting, does not
touch nftables, and starts nothing. Every call gets a `tunnel_service_test`
audit entry with the agent/service identifier, the protocols, the listener and
target ports and the results; token, key or PSK never go into the log. For a
disabled agent or service, or an unknown identifier, the operation is rejected
with an English error.

#### Home agent

In the `deploy/tunnel-agent/` directory:

- `agent.py` — Python stdlib only. It reads `agent.json` (by default
  `/etc/dropjak/agent.json`, a read-only mount in the compose). A version 2
  config first enrolls: it generates the keys (the private key reaches
  `wg pubkey` only on stdin), saves them to
  `/var/lib/dropjak-agent/identity.json` (0600) before the call, POSTs to
  `enroll.url` (redirects are not followed, an `enroll.url` inside
  `10.77.0.0/24` is rejected) and stores the sync token there. Transient
  failures (network, 429, 5xx) are retried with back-off up to 5 minutes; a
  refusal is final (exit 3 after a 5-minute pause). A restart with the same
  bundle reuses the identity offline; a bundle with a new token (re-enroll)
  gets new keys. A version 1 (legacy) config carries its keys and skips this.
  Then it sets `ip_forward`, then installs the `inet dropjak_agent` nft table **before**
  creating `wg0`. The rules are valid in its own network namespace:
  - `input`: drop by default; established/related and loopback.
  - `forward`: drop by default; every service to its own target interface
    (`iifname "wg0" oifname "<bridge>"`) to the resolved container IP and
    target port, and the reverse established on the same bridge.
  - `output`: drop by default; loopback, Docker DNS (`127.0.0.11:53`), the
    `resolv.conf` nameservers (rootless Podman's gateway), the cloud endpoint
    UDP, the `10.77.0.1:8100` sync and established. No other internet, LAN or
    host gateway is allowed.
  - `prerouting`: `wg0` tunnel port → DNAT to the resolved container IP:port.
  - `postrouting`: a separate `10.77.0.0/24 → masquerade` on every actually
    used attached interface, so that the service's reply comes back through
    the agent.
- **One network:** the agent connects to exactly one bridge network shared
  with the playit.gg agent. It resolves the target IP from the attached
  subnet; the target can only be a container address of this subnet: the
  bridge gateway (the host), the network/broadcast address, the agent's own
  address and an address outside the attached subnet are rejected. On error
  the whole sync is fail-closed, the last good rule set remains in effect.
- It re-resolves the target names on every sync (Docker's built-in DNS, by
  container name), and saves the last good configuration into a 0600 file. The
  `wg0` `allowed_ips` value may, according to the configuration check, only be
  part of `10.77.0.0/24`, so it cannot divert all traffic.
- `compose.example.yml` — a working example: the agent and one service on the
  same normal bridge network; no `internal: true`, no separate outbound
  network. The example `container_name` is
  `dropjak-tunnel-agent-home-home-1` (the installer writes the real name),
  `cap_drop: ALL` + `NET_ADMIN`,
  `no-new-privileges`, read-only rootfs, tmpfs, the configuration read-only
  (`:ro,Z`, so that it can be read on a SELinux host too), and `sysctls:
  net.ipv4.ip_forward=1` (in rootless Podman /proc/sys is read-only).
- `compose.agent.yml` — a static example (with English comments): exactly one
  network (`playitgg-net`, `external: true`), the agent on the bridge shared
  with the playit.gg agent; the downloaded installer regenerates this with the
  selected one network (interactive list, `DROPJAK_NETWORK` or the default).
- `check-containment.sh` — can be run on the home host, it modifies nothing;
  its output is in English: it checks that the Dropjak tunnel agent is running,
  is attached to **exactly one** bridge network (zero or more networks is an
  error), cannot be on the host/none network, the driver is bridge, when
  `DROPJAK_NETWORK` is given the attached network matches it, the host's
  Docker/Podman socket is not in it, and the read-only rootfs, the
  `no-new-privileges`, the `cap_drop: ALL` and the only `NET_ADMIN` capability
  are valid. It resolves the container name in this order: the
  `DROPJAK_CONTAINER` environment variable, the run directory's
  `container-name` file, and finally discovery of containers starting with the
  `dropjak-tunnel-agent` prefix. It uses a single match; with zero matches it
  warns about the installation; with multiple matches (several agents on one
  host) it exits with an error, lists the names, and asks to set
  `DROPJAK_CONTAINER=<name>`. Exit: 0 = OK, 1 = deviation, 2 = the check did
  not run.
- `Dockerfile` — `python:3.12-alpine` + `wireguard-tools`, `nftables`,
  `iproute2`.
- `selfinstall.sh` — the prefix of the downloaded installer (all its output
  and comments in English); at the end comes the tar.gz package, so a single
  file has to be carried to the other machine. It is idempotent, and selects
  the network interactively on a TTY, from a numbered list: it lists every
  bridge-driver Docker network (`N) name (bridge, N containers)`,
  `playitgg-net` first), then waits for the `Network [1-N] (default: ...)`
  question. An empty answer accepts the default (`playitgg-net`, if present;
  otherwise the network of the running playit container; otherwise the first
  candidate); on an invalid answer it asks again up to three times, then stops
  with an error. With non-interactive input (stdin not a TTY, or
  `DROPJAK_NO_PROMPT=1`) it does not ask: it uses the value of
  `DROPJAK_NETWORK`, otherwise the same default. `host`/`none`, non-bridge and
  non-existent networks are rejected; if there is no bridge candidate at all,
  it asks for `DROPJAK_NETWORK=<network>`. The agent always connects to exactly
  the selected one network, not to all networks, and does not fall back to
  `bridge`. The `delete` (or `--delete` / `-d`) first argument removes the
  agent's container: it derives the name from the installation directory's
  `container-name` file, failing that from `agent.json`, and as a fallback also
  tries the old fixed `dropjak-tunnel-agent` name. In the case of an existing
  compose file `docker compose down --remove-orphans` (named volumes, including
  `agent-state`, remain), otherwise `docker rm -f <name>`; if there is nothing
  to delete, it prints that and exits with 0.
  When started on a TTY, a two-line menu (`1) Install/update (default)`,
  `2) Delete container`) also offers deletion. On update it removes the earlier
  multi-network installation's `reconcile-networks.sh` helper and the
  `dropjak-agent-networks.timer` units.

#### Container name and multiple agents on one host

The installer derives the container name from the `agent.label` and `agent.id`
fields of the packaged `agent.json`:

```
dropjak-tunnel-agent-<label-slug>-<id>
```

The `label-slug` is lowercase ASCII: it transliterates the Hungarian accents
(`áéíóöőúüű` → `aeiououu`, and also their uppercase counterparts), replaces
every other non-`[a-z0-9]` character sequence with a single `-`, trims the
edges, and shortens the name to at most 63 characters. For an empty label (or a
label consisting only of symbols) the name is `dropjak-tunnel-agent-<id>`; if
there is no `agent` object in `agent.json` (an old package), the installer uses
the earlier fixed `dropjak-tunnel-agent` name. Examples:

| Label | id | Container name |
|---|---|---|
| `Home` | `home-1` | `dropjak-tunnel-agent-home-home-1` |
| `Árvíztűrő Tükörfúrógép` | `kert-1` | `dropjak-tunnel-agent-arvizturo-tukorfurogep-kert-1` |
| (empty) | `empty-7` | `dropjak-tunnel-agent-empty-7` |

The label provides recognizability, the id provides uniqueness: the names of
two agents with the same label also differ. The installer writes the resolved
name into the `container_name` field of `compose.yml`, and places a
`container-name` file (0644) next to the compose file; the `delete` operation
and `check-containment.sh` use this. Multiple agents on one host work if each
goes into a **separate installation directory** (the compose project and the
`agent-state` volume are also created per directory): the name identifies
them, the separate directory separates their compose resources.

#### Setup

1. Admin → Tunnels: save the endpoint and the WireGuard port.
2. New agent; the UI shows the one-time enrollment token, then immediately
   downloads the installer. Run it within 30 minutes; otherwise re-enroll.
3. The "Telepítő letöltése" (Download installer) button (offered while the
   page holds a valid token, or for a legacy agent) gives a single
   `dropjak-agent-<id>.sh` file. It is self-extracting: the beginning is the
   installer, at the end the `compose.yml`, `agent.json` (0600; the
   single-use enrollment token, or for a legacy agent its private key and
   token — to be handled confidentially), and the agent source
   (`agent.py`, `Dockerfile`, `check-containment.sh`). After the download the
   agent card shows the file's SHA-256 (from `X-Dropjak-SHA256`) in
   `sha256sum` format; compare it with `sha256sum dropjak-agent-<id>.sh` on
   the target machine before running it.
4. Copied to the other machine: `sudo sh dropjak-agent-<id>.sh`. The installer
   (all its output in English) installs into the current directory (`$PWD`, or
   `DROPJAK_DIR`). When started on a TTY, a small menu offers the operation:
   `1) Install/update (default)` and `2) Delete container`. The install/update
   checks for the presence of Docker/Compose, then asks for the network
   **interactively**: it lists the bridge-driver networks
   (`1) playitgg-net (bridge, 1 container)`, …), and waits for the
   `Network [1-N] (default: ...)` question. An empty answer accepts the
   default (`playitgg-net`, if present; otherwise the playit container's
   network; otherwise the first candidate); on an invalid answer it asks
   again for up to three attempts, then stops with an error. In non-interactive
   use (stdin not a TTY, `DROPJAK_NO_PROMPT=1`, for example
   `sh bundle.sh < /dev/null` or CI) it does not ask: it uses the value of
   `DROPJAK_NETWORK`, otherwise the same default, so it never gets stuck. If
   there is no bridge candidate at all, the installer stops with an error and
   asks for `DROPJAK_NETWORK=<network>` – it does not connect to all networks,
   and does not use `bridge` as a fallback. The selected network must exist and
   its driver must be `bridge` (`host`/`none` and a non-bridge network are
   rejected), and **exactly one** network goes into the compose. The compose
   contains a single `external: true` network, without a host-gateway entry;
   then it starts the agent with `docker compose up -d --build`, and prints the
   exact delete command. The `container_name` is derived from the packaged
   `agent.json`'s `agent.label` and `agent.id` fields
   (`dropjak-tunnel-agent-<label-slug>-<id>`, at most 63 characters), and the
   installer also writes it into a `container-name` (0644) file next to the
   compose file; the output includes the name and the
   `DROPJAK_CONTAINER=<name> check-containment.sh` command. Multiple agents on
   one host use a separate installation directory. On update, the earlier
   `reconcile-networks.sh` helper and the `dropjak-agent-networks.service/.timer`
   units are deleted (the timer disabled with `systemctl`). The generated files
   belong to the running user (root when run as root), `agent.json` is 0600.
   Removing the agent: `sudo sh dropjak-agent-<id>.sh delete` (or
   `--delete` / `-d`). This does not install and does not ask for a network; it
   resolves the name based on `container-name`/`agent.json`, with an existing
   compose file runs `docker compose down --remove-orphans` (named volumes
   remain), otherwise `docker rm -f <name>`; the old fixed
   `dropjak-tunnel-agent` name is always tried as a fallback. If there is
   nothing to delete, it prints this and exits with 0.
5. Your services can stay on the network shared with the playit.gg agent;
   in the cloud the target is the container's name and port (e.g.
   `purpur:25565`). Only a container on this network is reachable; a service
   running on the host is not a tunnel target: the bridge gateway (the host)
   is rejected according to `agent.py`'s check. There is no automatic
   multi-network reconciliation: attach a new service to this same one network.
6. The agent syncs at the given interval (by default 30 s); the services can be
   edited immediately in the cloud.
7. Create and assign an access rule for the public port; the client selects it
   after signing in to the portal.

#### Limitations and risks

- **Client IP:** the cloud masquerades to `10.77.0.1` towards the tunnel,
  otherwise the agent's WireGuard `allowed-ips` would drop the packet.
  Therefore the home service sees the cloud's WG address, and the cloud sees
  the agent's address; the real client IP does not reach home. Portal
  authorization and fail2ban, however, work in the cloud, with the real client
  IP.
- **One public UDP port** (by default 51820) opens in the cloud, only when an
  agent is enabled. WireGuard is the receiving side; it does not respond to
  unknown sources, and a handshake requires the key and the PSK.
- **The tunnel is not a general VPN:** only the configured TCP/UDP ports pass
  through, no UDP broadcast/multicast. The home LAN, the host and the internet
  are not reachable from the tunnel; the agent also narrows the address given
  as a target to a container address of the connected subnet, and rejects the
  bridge gateway (host) and the network addresses.
- **The agent is on exactly one network shared with the playit.gg agent:**
  this is the playit.gg model. The nft rules are valid only in the agent's own
  network namespace, they do not affect the service containers' own traffic.
  No other network is reachable from the agent; there is no automatic
  multi-network reconciliation, and the forward chain permits only the
  configured target IP:port pairs. The host Docker socket is not in the
  container, and the capability is limited to `NET_ADMIN`.
- **IPv4** only, as with the port proxy; the MTU is 1420. The WireGuard UDP
  port (by default 51820) cannot at the same time be a service listener port:
  with an agent enabled the save rejects this, otherwise the handshake would
  be directed to the proxy.
- **Port limit and reference:** at most 256 ports can be mapped per service,
  per agent and per mapping; the listener ports are unique in the namespace
  shared with the port proxies. A service referenced by a service or collection
  rule cannot be deleted while the reference exists (it can, however, always
  be disabled, in a fail-closed manner); changing the mapping or the enabled
  state recalculates the grants of the referencing rules, and revokes the
  changed sessions.
- **Restart:** when the portal container restarts, `dropjak0` disappears, then
  is recreated when the portal starts; the tunnel is suspended until then. The
  WireGuard keys reach `wg` via the tmpfs, through a 0600 temporary file, not
  on the command line.
- **Configuration export:** the format-2 package also carries the `tunnels`
  section: the server key pair, agent public keys, PSKs and token hashes
  (legacy agents: also their private keys and tokens until re-enrolled),
  therefore the package is confidential. A
  factory reset also deletes the tunnels, and removes the peers.

<a id="domain-proxy"></a>
## 4. Domain proxy

<a id="caddy-proxy-terv"></a>

### 4.1 Plan: Caddy reverse proxy and automatic TLS

_Source: `docs/caddy-proxy-terv.md` (original title: "Integration of a Caddy-style reverse proxy and automatic TLS into Dropjak")._

**Date:** 2026-10-20

**Status: implemented (3.4.0), deviating from the plan:** static `deploy/Caddyfile` without admin API and reload; the routes are portal-gated (`/api/proxy/ask`, `/api/proxy/auth` forward_auth). See the "Subdomain proxy (Caddy)" section of the README. The text below is the original plan.

**3.10.0:** the Unix socket admin API deferred to phase 2 has been completed, more narrowly than planned: `admin unix//run/caddy-admin/admin.sock|0666` on the `caddy-admin` volume mounted only into the portal and Caddy containers (directory `root:hatarvedelem 0750`), without a TCP port. The configuration remains static; the portal's only call is `POST /stop` (cache flush when ACME is disabled, see [4.2 Domain proxy log](#domain-proxy-naplo)).

This document contains only a plan. The proposal was not implemented; apart from creating `docs/caddy-proxy-terv.md`, no change was made in the repo, no commit, installation or host firewall modification was made.

---

#### 1. Executive summary

The proposal: forwarding a domain or subdomain to a port, with automatic SSL, Caddy-style. Dropjak is currently a captive-portal-based network gateway protected by a fail-closed nftables firewall, running in Docker `network_mode: host` mode and programming the host's `inet hatarvedelem` nftables table. The goal is an extension that makes public HTTP(S) services available under a domain name, with an automatic certificate, without violating the existing access-control invariants.

**Proposed architecture:**

- a separate **Caddy container** running in host network mode, with a lifecycle independent of the Dropjak portal container;
- the portal applies the generated configuration through the **Caddy admin API** (`POST 127.0.0.1:2019/load`, `Content-Type: text/caddyfile`);
- domain → port mappings are stored by the portal's new `proxy-settings.json` state file, and managed in the admin UI on a new **Proxy** tab;
- we do **not DNAT** WAN 80/443, because host-local Caddy receives the traffic on the `input` hook; we use a new, initially empty `proxy_wan` nft chain, to which the `input` chain jumps **after the fail2ban drop**;
- the portal **must not** be placed behind Caddy, because the portal uses the socket peer IP, and every client would appear as `127.0.0.1`;
- Minecraft/raw TCP is not HTTP; Caddy alone is not a solution for it; there the DNS SRV record and the existing portal rule are the right path.

**Key invariants that must not be violated:**

1. The `forward` chain remains fail-closed; the public proxy only opens 80/443 that are explicitly allowed.
2. A fail2ban ban also closes public 80/443; only the portal and DHCP remain reachable.
3. Host SSH remains reachable only with an active, authorized portal session, and only if a host (`input`) rule explicitly allowing TCP 22 is assigned to the session; one-off full-access and collection rules do not open it.
4. If the portal or Caddy fails to start, no new access is opened.
5. The proxy configuration is admin-only and cannot be introduced into the portal state or the Caddy admin API without authorization.

---

#### 2. Starting state and constraints

##### 2.1. Network and firewall model

- The Dropjak container runs in `network_mode: host` mode (`docker-compose.yml:16`), with `read_only: true` (`:21`), `cap_drop: ALL`, and receives only `NET_ADMIN`, `NET_BIND_SERVICE`, `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID` capabilities (`:27-36`). State is in a Docker volume (`:121-122`), the healthcheck polls `/api/status` (`:133-138`).
- Both the `input` and `forward` chains of the nftables table are `policy drop` (`deploy/dropjak.nft:114-116`, `:133-137`). The `forward` chain has priority -10 so that it runs before Docker's own rules.
- The dynamic sets (`allowed_v4`, `allowed_tcp`, `allowed_udp`, `allowed_icmp`, `allowed_input_tcp`, `allowed_input_udp`, `client_mac`) expire with kernel timeouts; every restart clears them (`README.md:21-31`).
- Pre-auth and block rules live in the `forward` chain and in the `preauth`/`block`/`preauth_nat`/`block_nat` custom chains (`deploy/dropjak.nft:109-112`, `gateway.py:1839-1954`). In the pre-auth WAN direction, they match only DNATed traffic (`ct status dnat`, `gateway.py:1919-1927`).
- The system examines the pre-DNAT port using `ct original proto-dst` (`deploy/dropjak.nft:198-200`), because Docker's own DNAT may run in the same prerouting stage.
- In Docker's `DOCKER-USER` chain, a guard only allows packets marked with `FWD_MARK` and drops everything else (`docker/entrypoint.sh:160-222`). This protects even if the `hatarvedelem` table disappears.
- From the LAN, TCP 80 is redirected to the portal (`deploy/dropjak.nft:372`); the redirect with the `iifname "__LAN_IF__"` condition matches only the LAN interface.
- WAN → LAN traffic is masqueraded (`deploy/dropjak.nft:375-377`).
- IPv6 inbound traffic is dropped by both the `input` and `forward` chains (`deploy/dropjak.nft:147-148`, `:256-257`).

##### 2.2. Fail2ban and portal behavior

- The `banned_v4` drop in the `forward` chain is before the allowing rules (`deploy/dropjak.nft:168-169`).
- In the `input` chain, portal acceptance is **before** the ban drop (`deploy/dropjak.nft:279-280`), so that a banned client can also see the ban screen; the ban drop follows (`:281-282`). All other host services and forward traffic are dropped during a ban.
- The portal uses the socket peer IP: `_client_ip()` (`server.py:72-76`). There is no `X-Forwarded-For` support.
- The admin API uses `_admin_guard`, `_origin_ok` (`server.py:93-105`) and a JSON-only body (`server.py:143-163`) for protection; the settings modification pattern is `_admin_settings_action` (`server.py:675-743`): admin guard → origin check → lock → `settings.prepare` → `gw.apply_settings` → audit, on error 400/503, state unchanged.
- `Gateway.apply_settings()` (`gateway.py:4228-4272`) first applies to nftables, then commits; on a commit error it restores the previous rules. This pattern should be followed for proxy settings too.
- `Gateway.start()` (`gateway.py:4274-4279`) starts the reaper, audit and drop log threads; a proxy reconciler thread also belongs here.

##### 2.3. Current UI and state

- Admin navigation includes the Users/Groups/Rules/Sessions/Firewall/Drops/Fail2ban/Logs/Settings tabs (`index.html:934-942`).
- The Settings tab manages two sections: pre-auth and block (`README.md:246-266`); the UI is built on the `settingsData()`, `renderSettingForm()`, `renderSettingSection()` and `renderSettings()` functions (`index.html:4773-5004`). Host SSH is not a setting: it is opened only by a host rule assigned to the user that explicitly allows TCP 22.
- Tab dispatch is `index.html:6314-6321`; the HU/EN/DE i18n tables are in the same file; the raw firewall view's chain labels are `index.html:5596-5599`.
- `settings_store.py` validates and atomically writes `firewall-settings.json` (`:126-196`, `:199-366`); on a corrupt file it falls back to empty pre-auth/block lists (fail-closed).
- Contents of the state volume: `users.json`, `groups.json`, `rules.json`, `audit.jsonl`, `drops.jsonl`, `fail2ban.json`, `firewall-settings.json` (`README.md:268-282`).
- The portal runs on plain HTTP; TLS currently must be solved with an external reverse proxy or a trusted management network (`README.md:293-296`).

##### 2.4. Constraints

- Host SSH is portal-gated and opens only with a host rule assigned to the user that explicitly allows TCP 22; a one-off full-access or collection rule does not open it. The proxy integration must not open management access.
- The fail-closed model cannot be relaxed; the proxy may open only separate, explicitly allowed public ports.
- The research was read-only; this document is also a plan, not an implementation.
- The `docs/` directory was created with the document; no other file changed.

---

#### 3. Architecture options

##### A) Separate Caddy container, `network_mode: host`, with Admin API (recommended)

Caddy listens on 80/443 in the host network; the portal reaches the `127.0.0.1:2019` admin API in the same network namespace.

**Advantages:**

- WAN 80/443 is host-local traffic, so it goes through the `input` hook; no DNAT, `FWD_MARK` or `DOCKER-USER` integration is needed.
- The client source IP is preserved throughout, so the `banned_v4` drop, the drop log and fail2ban work unchanged.
- Caddy reaches Docker-published ports (`127.0.0.1:<hostport>`) and container networks; host → container traffic does not pass through the `forward`/`DOCKER-USER` chain.
- The portal and Caddy lifecycles are separated: restarting the portal does not drop public sites, and updating Caddy does not affect portal state.
- No Docker socket mount, no shared filesystem, no `docker exec`.

**Disadvantages:**

- Because of the host network, Caddy can reach every host port and container IP (SSRF-like risk); it must be curbed with config validation and a denylist.
- Binding 80/443 requires root or `NET_BIND_SERVICE`.
- The admin API listens on loopback without authentication; any process on the host can reconfigure it (Unix socket in phase 2).

##### B) Separate Caddy container on a bridge network, with published 80/443

**Advantage:** a more isolated container, not root in the host network.

**Disadvantages:**

- Because of the DNAT for published ports, traffic goes through the `forward` chain; another exception must be inserted between the existing pre-DNAT port matching (`deploy/dropjak.nft:198-200`) and the `DOCKER-USER` guard (`docker/entrypoint.sh:160-222`).
- Caddy cannot reach `127.0.0.1:<published port>`, only the host IP or the container IP, which depends on hairpin/NAT.
- More moving parts, more failure windows.

**Not recommended for v1.**

##### C) Building Caddy into the Dropjak image

**Disadvantages:**

- The portal container's `NET_ADMIN` and state volume are mixed with an internet-facing TLS terminator.
- Caddy and portal upgrades become coupled.
- Restarting the portal also drops the public sites.
- Image size and attack surface increase.

**Not recommended.**

##### D) Own config generation into a file + `caddy reload`

Same config generation as A, but the Caddyfile goes onto a shared volume, and the portal reloads via `docker exec`/signal. This requires extra privilege (Docker socket or exec) and is not an atomic reload. **The Admin API `POST /load` is atomic; on error the previous config remains in effect** — so we stay with A.

##### E) One Caddy per host

One instance is enough; Caddy can serve multiple sites and routes. Multiple instances would only be justified for isolation/multi-tenancy, which is not a goal.

##### Comparison

| Aspect | A) host + Admin API | B) bridge + published port | C) built-in | D) file + reload |
|---|---|---|---|---|
| nft complexity | low (input accept) | high (DNAT, FWD_MARK, DOCKER-USER) | low | low |
| Source IP preserved | yes | yes | yes | yes |
| Host-local upstream | yes | no/sometimes | yes | yes |
| Lifecycle isolation | good | good | bad | good |
| Atomic reload | yes | yes | yes | no |
| Extra privilege | none | none | image merge | Docker socket/exec |
| v1 recommended | **yes** | no | no | no |

**Decision:** option A, as a separate compose service, with an image pinned to an exact version, and the Dropjak portal as the Caddy admin API client.

---

#### 4. Domain → port mapping: UI, storage, generation, reload

##### 4.1. Data model and storage

A new state file following the existing pattern: `proxy-settings.json` in the state volume (`/var/lib/hatarvedelem`), mode `0600`, atomic write (`mkstemp` + `fsync` + `os.replace`), following the pattern of `settings_store.py:199-366`.

```json
{
  "version": 1,
  "enabled": true,
  "acme_email": "admin@example.com",
  "acme_staging": false,
  "routes": [
    {
      "id": "r-1a2b3c4d",
      "label": "Nextcloud",
      "host": "cloud.example.com",
      "upstream": "127.0.0.1:8080",
      "enabled": true
    }
  ]
}
```

Validation following the pattern of `settings_store.py:126-162`:

- `host`: required, lowercase FQDN, strict regex (only `a-z0-9.-`, at least one dot, max 253 characters), no wildcard, no port, no scheme/path; `localhost`, the portal hostname and the Caddy admin host are forbidden. This is also protection against Caddyfile injection.
- `upstream`: `host:port` form, host = IPv4 or Docker container name/IP, port 1-65535; `169.254.0.0/16`, `0.0.0.0`, multicast, as well as `127.0.0.1:22`, `:53`, `:67`, `:68`, `:2019`, `:8100` (portal) and the host SSH port are forbidden. The denylist should be in code, not in the UI.
- `id`: following the existing `_ID_RE` pattern; `label` max 64 characters.
- Duplicate `host` is not allowed; `routes` max ~64 entries.
- Corrupt/missing file → **fail-closed**: `enabled=false`, empty route list, audit entry; the portal attempts to apply an empty Caddy config.

##### 4.2. Admin API

New admin endpoints, following the existing pattern (`server.py:675-743`):

- `GET /api/admin/proxy` → the stored state + Caddy status (`reachable`, `last_apply_ok`, `last_error`).
- `POST /api/admin/proxy` → `{"action":"save", "enabled":..., "acme_email":..., "acme_staging":..., "routes":[...]}`; optionally `{"action":"sync"}` to reapply.
- Required: `_admin_guard`, `_origin_ok` (`server.py:93-105`), JSON-only body (`_read_json`, `server.py:143-163`), separate `proxy_lock`, audit (`admin_proxy_changed`, `admin_proxy_apply_failed`). On error 400 (validation) or 503 (Caddy unreachable), the state is not persisted.

##### 4.3. Caddyfile generation

The portal produces the text from the validated state; it does not template raw user strings.

```caddyfile
{
	admin 127.0.0.1:2019
	email admin@example.com
	# only in staging mode:
	acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
	servers {
		protocols h1 h2
		strict_sni_host on
	}
}

cloud.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

- `protocols h1 h2`: disabling HTTP/3 (UDP 443) in v1, so UDP 443 does not need to be opened.
- No catch-all site and no default upstream: an unknown Host/SNI gets no route.
- `reverse_proxy` automatically handles WebSocket, sets the `X-Forwarded-For/Proto/Host` headers, and by default ignores the client-supplied XFF.

##### 4.4. Application, reload, rollback

1. validation → rendering the Caddyfile;
2. `POST http://127.0.0.1:2019/load`, `Content-Type: text/caddyfile`, short timeout (5 s);
3. on success, updating the `proxy_wan` nft chain (see point 5), then atomic commit of `proxy-settings.json`;
4. on failure of any step, restoring the previous Caddyfile and the previous nft state, state remains unchanged.

At startup Caddy starts after the portal (`depends_on: dropjak: condition: service_healthy`), so it is not yet available during `prepare()`. Next to `Gateway.start()` (`gateway.py:4274-4279`) there should be a **reconciler thread**: it tries to apply the desired config with exponential backoff, then periodically (e.g. 60 s) checks reachability. Because of Caddy's `/config` autosave, a Caddy restart restores the most recently applied config; the portal only diverges if Caddy was down when the setting changed — this is indicated by the failed apply, and the reconciler catches up. For detailed operation, Caddy's `/data` and `/config` volumes are mandatory.

##### 4.5. UI

A new admin tab in the existing navigation (`index.html:934-942`), following the Settings pattern (`index.html:4773-5004`):

- master enable;
- ACME email;
- staging checkbox;
- route table: host, upstream, enabled, status;
- add/edit/delete;
- Caddy status and last error.

Tab dispatch (`index.html:6314-6321`) and the HU/EN/DE i18n tables must be extended. In the Firewall → Raw rules view, the label of the new `proxy_wan` chain also appears (`index.html:5596-5599`, `gateway.py:160-170`).

##### 4.6. Stored data and backup

`proxy-settings.json` is part of the state volume, so it fits into the existing backup procedure (`README.md:268-282`). Caddy's own volumes (`caddy-data`, `caddy-config`) must be handled separately; `deploy/hv backup` and the documentation should be extended with them. `/data` contains the ACME account key and private certificate keys, so the backup must be encrypted.

---

#### 5. nftables plan

##### 5.1. Why input, and not DNAT

Since Caddy runs in the host network, WAN 80/443 **arrives at the host's own address**, so it goes through the `input` hook. The existing WAN pre-auth rules (`ct status dnat`, `gateway.py:1919-1927`) only match DNATed traffic, so they do not apply to Caddy. A bridge Caddy would require DNAT + `FWD_MARK` + `DOCKER-USER`, but we rejected that.

##### 5.2. New chain

In the template, next to the existing custom chains (`deploy/dropjak.nft:109-112`):

```nft
add chain inet hatarvedelem proxy_wan
```

Loading the template does **not** clear it (unlike the preauth/block chains); the portal's `clear_proxy()`/`apply_proxy()` functions handle it, and it is also added to the `RULESET_CHAINS` tuple (`gateway.py:160-170`) because of the raw view.

##### 5.3. Insertion point in the input chain

Order is key. In the current input chain, portal acceptance is **before** the ban drop (`deploy/dropjak.nft:279-280`), and the ban drop is `:281-282`. The new jump should go **after line 282**:

```nft
# after fail2ban drop: a banned source cannot reach public 80/443 either
iifname "__WAN_IF__" jump proxy_wan
```

The `proxy_wan` chain is initially empty. If the proxy is disabled, or there is no enabled route, the chain remains empty → `policy drop` applies, nothing opens. If active:

```nft
add rule inet hatarvedelem proxy_wan iifname "__WAN_IF__" tcp dport 80 accept
add rule inet hatarvedelem proxy_wan iifname "__WAN_IF__" tcp dport 443 accept
```

- **Fail2ban precedence:** since the jump is after `banned_v4 drop`, a banned IP cannot reach the public sites either. This is the mandatory invariant; the jump **must not** be placed before line 281. The existing preauth pattern reinforces this: the first rule of the preauth chain is also the ban drop (`gateway.py:1861-1864`).
- **LAN redirect:** the portal redirect `iifname "__LAN_IF__" ... tcp dport 80 redirect to :__PORT__` (`deploy/dropjak.nft:372`) matches only the LAN interface; it does not affect WAN 80. From the LAN, HTTP still goes to the portal.
- **LAN 443:** if internal clients also want to reach the public routes on the public IP (hairpin), an `iifname "__LAN_IF__" tcp dport 443 jump proxy_wan` is also needed; this does not grant more rights, since the same service is public from the WAN anyway. In v1 I recommend this as a switch, **off** by default, and documenting that the portal still answers LAN HTTP.
- **Pre-auth/block semantics:** these rules live in the `forward` chain and do not affect host-local Caddy. The block list therefore does **not** block the public proxy route; this must be documented, because it can be misleading. The proxy does not need to be added to the pre-auth list.
- **Docker-USER guard:** unaffected. Host-local 80/443 is input, and Caddy's host → container upstream traffic is locally generated, so it does not pass through the `forward`/`DOCKER-USER` chain. The guard (`docker/entrypoint.sh:160-222`) remains unchanged.
- **Drop-log/fail2ban behavior:** WAN 80/443 previously generated `input-wan` drop events, and drop-based banning saw port scanners. After this, these packets pass to Caddy, so drop-based ban will not see them. Login brute-force and other drop reasons are unchanged. In phase 2, fail2ban integration can be built from the Caddy access log.
- **IPv6:** because of the input chain's IPv6 drop (`deploy/dropjak.nft:256-257`), Caddy is reachable only over IPv4. There should be **no** AAAA record in DNS for the proxy hostnames, otherwise IPv6-preferring clients hit a wall. IPv6 is a separate project.
- **Native installation:** the default `PORT=80` of `install.sh` conflicts with Caddy binding 80. The Caddy integration in v1 assumes Docker compose mode; in native mode the portal must be reconfigured, or Caddy will not start.
- **Portal outage:** the nft rules remain in the kernel and the public routes continue to live; this is acceptable for public services. When the portal restarts, `prepare()`/`_apply_custom_settings()` reapplies the `proxy_wan` chain from the persisted state; on corrupt state an empty chain (fail-closed).

##### 5.4. Fail-closed behavior

- If `proxy-settings.json` does not exist or is corrupt: `enabled=false`, empty `proxy_wan` → 80/443 closed due to `policy drop`.
- If Caddy fails to start, the portal does not open the `proxy_wan` chain even if the state is enabled; the apply step aborts on the Caddy error and the state is not committed.
- If the portal dies, the rules left in the kernel remain in effect; Caddy serves the last good config. No new route is created.
- Template reload does not clear the `proxy_wan` chain, just as it does not clear the preauth/block chains (`deploy/dropjak.nft:102-112`).

---

#### 6. ACME / SSL

##### 6.1. DNS requirements

- A public **A record** to the WAN IP for every route. The record must be set before certificate issuance; HTTP-01/TLS-ALPN-01 requires a hostname that is already reachable at the moment of issuance.
- **AAAA record not recommended**, because nft drops IPv6 inbound traffic (`deploy/dropjak.nft:256-257`). If the hostname also has an AAAA, IPv6-preferring clients will reach nothing.
- **CAA:** if there is a CAA record, `letsencrypt.org` must be allowed; Caddy defaults to Let's Encrypt, falls back to ZeroSSL on error, so either allow both, or pin Let's Encrypt with `acme_ca`.
- DNS must be configured before enabling the proxy, otherwise Caddy consumes the rate limit with failed authorizations.

##### 6.2. Challenge types

- **HTTP-01:** on port 80; Caddy serves it automatically.
- **TLS-ALPN-01:** on port 443; Caddy serves it automatically.
- Both are active by default; ports 80 and 443 must be open (the `proxy_wan` rules). If the provider blocks 80, TLS-ALPN-01 alone is enough.
- **DNS-01:** only for wildcard or for cases where 80/443 is not reachable from outside. The official Caddy image **does not include** DNS provider modules; a custom build must be made with xcaddy (e.g. `github.com/caddy-dns/<provider>`), plus an API token secret. This is phase 2.

##### 6.3. Wildcard

- `*.example.com` can only be issued via DNS-01.
- The wildcard covers only one left-hand label (`*.example.com`, not `a.b.example.com`).
- Caddy 2.10+ can reuse the wildcard cert for configured subdomains, which reduces the number of issuances.
- A custom build is required instead of the standard image; the DNS API token must be stored as a secret, not in `proxy-settings.json`.

##### 6.4. Renewal and storage

- Caddy renews automatically about one third before expiry; no cron is needed.
- The condition is a persistent `/data` volume (ACME account key + certs). If the volume is lost, reissuance counts toward the rate limit.
- The `/config` volume stores Caddy's autosave; without it, the last config is not restored after a restart.
- `/data` contains private keys; the volume permission is 0700, the backup is encrypted.

##### 6.5. Email and staging

- The ACME email is recommended (expiry notifications), not mandatory.
- For testing `acme_ca https://acme-staging-v02.api.letsencrypt.org/directory`; the staging cert is not trusted, and when going live it must be switched back and reissued.
- The staging toggle should be in the UI so we do not accidentally burn the production rate limit.

##### 6.6. Rate limits

| Limit | Value |
|---|---|
| Certificates / registered domain / 7 days | 50 |
| Same identifier set / 7 days | 5 |
| New order / account / 3 hours | 300 |
| Failed authorization / identifier / account / hour | 5 |
| Account / IP / 3 hours | 10 |
| Caddy's own experimental limit | 10 / account / 10 s |

Before going live use staging; failed attempts consume the above limits.

##### 6.7. On-demand TLS

Not used in v1. If ever added, only with `on_demand_tls { ask ... }`, otherwise the rate limit can be exhausted and the proxy becomes an open certificate factory.

##### 6.8. HTTP → HTTPS and the portal

- Caddy automatically redirects to HTTPS on 80; this works from the WAN.
- On the LAN, the portal redirect runs first (`deploy/dropjak.nft:372`), so the portal answers LAN HTTP. This is correct because of the captive portal.
- Do not put HSTS on the portal, because the portal runs on plain HTTP (`README.md:293-296`).

##### 6.9. Minecraft and raw TCP

- Caddy's HTTP reverse proxy **cannot** serve the Minecraft protocol, and "auto SSL" is not applicable to it.
- For Minecraft, the DNS SRV record (`_minecraft._tcp.play.example.com` → host:25565) + the existing portal rule/preauth is the right path; this is independent of the Caddy integration.
- For raw TCP, the `caddy-l4` plugin exists, but it is not auto-TLS and not v1.

---

#### 7. Security risks and mitigations

1. **Public exposure:** 80/443 opens to the internet, Caddy becomes the largest attack surface. Mitigation: image pinned to exact version, regular updates, standard (minimal-module) build, no `caddy-l4` in v1, no catch-all.
2. **SSRF-like upstream:** host-network Caddy can reach any host port and container IP (SSH, portal, admin API, Docker API, metadata). Mitigation: admin-only configuration, strict host/upstream validation, denylist, no default upstream, audit; in phase 3 a dedicated UID + nft output/egress restriction.
3. **Admin API without authentication on loopback:** any local process can reconfigure Caddy. v1: single-tenant host, documented assumption; phase 2: Unix socket (`admin unix//run/caddy/admin.sock`) with narrow permissions, mounted into the portal container.
4. **Do NOT proxy the portal:** `_client_ip()` (`server.py:72-76`) uses exclusively the socket peer address, not XFF. If the portal is placed behind Caddy, every client appears as `127.0.0.1`, and session IP binding, host SSH grant, fail2ban, the ban screen, as well as `_origin_ok` (`server.py:93-105`) and `_portal_host_matches` (`server.py:320-327`) break. If TLS is needed for the portal, trusted-proxy XFF support must first be built in (phase 3), or VPN/SSH tunnel should be used.
5. **Header hygiene:** Caddy overwrites XFF by default and ignores the incoming one; **never** set `trusted_proxies` to `0.0.0.0/0`. The backend should not blindly trust XFF. HSTS only if all affected names are HTTPS-only; do not put HSTS on the portal's domain. Phase 2: `strict_sni_host on`, security headers.
6. **Secrets:** `/data` contains the ACME account key and cert private keys — volume 0700, backup encrypted. DNS API token (phase 2) from Docker secret or 0600 `.env`, **never** into `proxy-settings.json` or the audit log. `.env` should remain 0600 (`README.md:321-323`).
7. **Fail2ban precedence:** the `proxy_wan` jump is after the ban drop; this must be tested (following the existing exact-string tests, `tests/test_gateway.py:3690-3829`) so that a ban cannot be bypassed.
8. **Change in drop-based banning:** WAN 80/443 no longer generates `input-wan` drops; port scanners reach Caddy. Phase 2: access-log-based fail2ban.
9. **DoS:** Caddy handles TLS/HTTP load; there is no rate limit in v1. Phase 2: plugin or upstream limit.
10. **Container hardening:** `read_only: true`, `cap_drop: ALL` + `NET_BIND_SERVICE`, `security_opt: no-new-privileges:true`, no Docker socket, journald log, exact image pin. Root-running Caddy is acceptable in v1, in phase 2 non-root + `setcap` or Unix socket.
11. **Backup:** `deploy/hv backup` and the README backup section (`README.md:268-282`) should be extended with the `caddy-data` and `caddy-config` volumes.

##### 7.1. Proposed compose skeleton

```yaml
caddy:
  image: caddy:<exact-version>
  network_mode: host
  read_only: true
  cap_drop: [ALL]
  cap_add: [NET_BIND_SERVICE]
  security_opt: ["no-new-privileges:true"]
  restart: unless-stopped
  volumes:
    - caddy-data:/data
    - caddy-config:/config
    - /etc/localtime:/etc/localtime:ro
  depends_on:
    dropjak:
      condition: service_healthy
  logging:
    driver: journald
```

The Caddy admin API should listen only on `127.0.0.1:2019`. The container must not receive `NET_ADMIN`, must not see the Docker socket, and must not receive a host PID namespace.

---

#### 8. Phases, MVP and estimates

##### 8.1. v1 — minimal, useful iteration

**Scope:**

- separate Caddy container in host network, hardened compose service;
- `proxy-settings.json` + validation + atomic write;
- `proxy_wan` nft chain + input jump after the ban drop, `clear_proxy`/`apply_proxy`, raw view;
- Caddyfile render + `POST /load` + rollback + startup reconciler;
- admin API (`GET/POST /api/admin/proxy`) with the existing guard/origin/lock/audit pattern;
- admin UI tab + HU/EN/DE i18n + route CRUD + staging toggle;
- explicit hostnames, HTTP upstream, HTTP/1.1+2, WAN-only, no wildcard, no DNS-01, no portal proxy;
- tests: nft exact-string, settings-store validation/corrupt fallback, API 400/503, Caddyfile rendering for injection cases;
- documentation (README + [2. Installation and operation](#telepites)).

**Out of scope:** wildcard, DNS-01, on-demand TLS, HTTP/3, IPv6, portal proxy, portal-gated routes, `caddy-l4`, rate limit, access-log fail2ban.

**Estimate:**

| Area | Hours |
|---|---|
| nft + gateway (`proxy_wan`, apply/clear, raw view) | 5-7 |
| settings store + validation | 4-5 |
| Caddyfile render + admin client + reconciler | 7-9 |
| API + audit | 4-5 |
| UI + i18n | 8-10 |
| tests | 6-8 |
| docs + compose | 3-4 |
| buffer / hardening | 3-7 |
| **Total** | **40-55** |

Sub-goals:

- **PoC** (only nft + manual Caddy config): 12-16 hours.
- **First useful iteration** (the above scope without UI polish and full test coverage): 24-32 hours.
- **Full, polished v1**: 40-55 hours.

##### 8.2. Phase 2 — hardening/ops (20-30 hours)

- Unix socket admin, non-root Caddy;
- cert status and Caddy logs in the UI;
- access log + fail2ban;
- wildcard DNS-01 custom build + secret;
- HSTS/security headers, `strict_sni_host`;
- LAN 443/hairpin switch;
- backup integration;
- rate limit.

##### 8.3. Phase 3 — advanced (30-60+ hours)

- portal-gated routes (with MAC binding; for this, host-input-side `allowed_tcp` MAC pairing is missing and must be added);
- on-demand TLS with `ask`;
- `caddy-l4` for raw TCP;
- IPv6;
- bridge/skuid isolation;
- multi-tenant.

---

#### 9. Testing plan

- **nft exact-string tests:** following `tests/test_gateway.py:3690-3829`, verify the creation of the `proxy_wan` chain, the exact position of the jump after the ban drop, the accept rules, and that with the proxy disabled the chain is empty.
- **Settings store tests:** following `tests/test_gateway.py:3532-3696`, validation, atomic write, corrupt file → fail-closed.
- **API tests:** following `tests/test_gateway.py:2819-2930`, admin guard, origin check, 400 invalid, 503 Caddy error, state unchanged.
- **Caddyfile injection:** rejection of `{`, `}`, newline, `#`, `;` characters placed in the hostname and upstream; an unknown Host gets no route.
- **Ban precedence:** a banned IP cannot reach 80/443, but can reach the portal and DHCP; after the ban is lifted, the proxy is reachable again.
- **Fail-closed:** no `proxy-settings.json` → empty `proxy_wan`; Caddy unreachable → no state commit; portal restart → reapply the persisted state.
- **Integration check:** on the <test-vm> test VM only in a later, separately approved phase; the current plan includes no installation.

---

#### 10. Open questions

1. **What is the concrete goal:** a public HTTP(S) web application, or Minecraft/raw TCP? For the latter, the Caddy integration is not justified; DNS SRV + portal rule is the solution.
2. **LAN 443 hairpin:** should internal clients be allowed to reach the public routes on the public IP? v1 proposal: separate switch, off by default.
3. **Corrupt `proxy-settings.json`:** empty route list (fail-closed) or keeping Caddy's last good config? v1 proposal: fail-closed, audited.
4. **Native installation:** is Caddy supported in native mode, or only Docker compose? v1 proposal: Docker only.
5. **Admin API:** does `127.0.0.1:2019` remain, or Unix socket? v1: loopback; phase 2: socket.
6. **HTTP/3:** off in v1; later with UDP 443 opening.
7. **Proxying the portal:** not recommended; if it is still needed, first trusted-proxy XFF support in the portal.

---

#### 11. Recommendation

**Conditionally yes.** If the goal is to make public HTTP(S) services (webapp, dashboard, API) available under a domain/subdomain with an automatic certificate, then the proposed architecture fits the Dropjak model, and the fail-closed/precedence invariants can be maintained. If the concrete goal is publishing Minecraft (or other raw TCP), then Caddy is not the solution: there DNS SRV + the existing portal rule is the right path, and the Caddy integration is not worth starting.

**This is worth building first:**

1. the `proxy_wan` nft chain + input jump after the ban drop (this is the smallest, independently testable security backbone);
2. the separate Caddy container + admin API Caddyfile apply + rollback;
3. `proxy-settings.json` + minimal admin UI/API;
4. only after that the convenience and ops features.

**What not to do in v1:**

- building Caddy into the Dropjak image;
- bridge Caddy;
- proxying the portal;
- wildcard/DNS-01;
- on-demand TLS;
- catch-all route;
- HTTP/3 (UDP 443);
- placing the `proxy_wan` jump before the ban drop.

---

#### 12. Appendix — referenced files and line numbers

| File | Relevant parts |
|---|---|
| `README.md` | 21-23 (fail-closed), 31-34 (host SSH), 35-39 (Docker), 40-49 (fail2ban), 50-53 (host network), 246-266 (settings), 268-282 (backup), 293-296 (TLS), 302-320 (security) |
| `docker-compose.yml` | 16 (host network), 21 (read_only), 27-36 (caps), 43-119 (env), 121-122 (state volume), 133-138 (healthcheck) |
| `deploy/dropjak.nft` | 109-112 (custom chains), 114-116 (input policy), 133-137 (forward policy), 147-148 (IPv6 forward), 168-169 (ban forward), 198-200 (pre-DNAT matching), 256-257 (IPv6 input), 279-282 (portal accept + ban drop), 313 (established), 324-325 (portal accept), 334 (host SSH), 342-345 (DNS), 349-350 (final logs), 372 (LAN redirect), 375-377 (masquerade) |
| `gateway.py` | 160-170 (`RULESET_CHAINS`), 1823-1837 (`clear_custom`), 1839-1954 (`apply_custom`), 1861-1864 (preauth ban drop), 4228-4272 (`apply_settings`), 4274-4279 (`start`) |
| `settings_store.py` | 126-162 (validation), 148-154 (TCP 80 block), 165-196 (`validate_state`), 199-366 (store) |
| `server.py` | 72-76 (`_client_ip`), 93-105 (`_origin_ok`), 143-163 (`_read_json`), 234-254 (`_admin_state`), 320-327 (`_portal_host_matches`), 675-743 (settings action), 846-869 (POST routes), 1852-1930 (`_serve`) |
| `index.html` | 934-942 (admin nav), 4773-5004 (settings UI), 5596-5599 (chain labels), 6314-6321 (tab dispatch) |
| `docker/entrypoint.sh` | 98-158 (ruleset render), 160-222 (DOCKER-USER guard), 252-280 (firewall load) |
| `deploy/dropjak-boot.nft` | boot guard; input policy is accept until the main table is loaded |
| `tests/test_gateway.py` | 2819-2930 (settings API), 3532-3696 (settings store), 3690-3829 (nft exact-string) |

---

*End — this document is a plan, not an implementation.*

<a id="domain-proxy-naplo"></a>

### 4.2 Development and deployment log

_Source: `docs/domain-proxy-naplo.md` (original title: "Domain proxy – development and deployment log")._

**Last update:** 2026-10-22 01:10
**Test VM:** <test-vm> (Debian 13, Docker)
**Live version:** 3.9.1 (deployed: 2026-10-22).
**Last commit:** `62cdabc` (3.6.0, uploaded to GitHub). Changes between 3.7.0 and 3.9.1 are not committed.
**In progress:** 3.10.0 (fix for disabled automatic certificate, being deployed) and 3.11.0 (Proxy tab, TCP/UDP port proxy; done locally, not deployed).

---

#### Overview

Dropjak received a built-in, Caddy-based reverse proxy. It forwards subdomains under the root domain (for example `teszt1.<test-domain>`) to services behind the firewall, with an automatic or uploaded HTTPS certificate. Dropjak decides on access: based on login, domain-type rules, visibility, challenge and fail2ban.

##### Architecture

- **Caddy:** separate container, `network_mode: host`, `caddy:2.10.2-alpine`, compose profile `proxy`. Fixed `deploy/Caddyfile`, without admin API; no reload at runtime.
- **Decision:** on every HTTP request, `forward_auth` calls the portal's `/api/proxy/auth` endpoint.
  - If allowed, the portal specifies the target in the `X-Dropjak-Upstream` header, and Caddy proxies to it.
  - If not allowed, the response is 401 (denial page) or 403 (challenge).
- **Certificates:**
  - `get_certificate http` → `/api/proxy/cert` serves the uploaded certificate.
  - If none is uploaded, on-demand ACME comes. This is enabled by `/api/proxy/ask`, only for listed names.
- **Client IP:** Caddy sends the real IP in the `X-Forwarded-For` header. The portal accepts it only from a loopback (127.0.0.1/::1) peer that also sends `HV_PROXY_KEY` (when it is set; give the same value to both services).
- **Firewall (nft):** TCP 80/443 opens only when `HV_PROXY=1`, after the fail2ban drop.
  - From the WAN, for everyone.
  - From the LAN, only for IP+MAC-bound clients.
- **Enabling (`.env`):** `HV_PROXY=1` and `COMPOSE_PROFILES=proxy`.

##### DNS (prerequisite)

- Two `A` records are needed: `<test-domain>` and `*.<test-domain>` → <test-vm>.
- On Cloudflare, "DNS only" (gray cloud), without AAAA record.
- `<other-domain>` is Cloudflare-proxied, so it cannot be used. `z2` is in use.

---

#### Versions

##### 3.4.0 – the base proxy (deployed)

- Caddy service, static Caddyfile, on-demand TLS with the `ask` endpoint.
- `/api/proxy/ask`, `/api/proxy/auth`, `/api/proxy/unauthorized.png`. Only loopback can call them.
- Denial page with the `unauthorized.png` image and an icon login button (the button is blue, rounded; the text is provided by `aria-label`).
- Settings: `proxy_domain` and `proxy_routes` (subdomain → port).
- nft: `__PROXY__` template placeholder for the 80/443 accept rules.
- Deployed. Backup: `hatarvedelem-20261021-165039.tar.gz`. The `.env` received two new lines.

##### 3.5.0 – Domains tab, input/forward, domain rule (deployed)

- Its own **"Domains"** admin tab; moved out from under Settings.
- **Entry types:**
  - `input`: `127.0.0.1:port`.
  - `forward`: private IP:port (10/8, 172.16/12, 192.168/16).
- **New rule type, "domain":** allows listed hostnames.
  - Does not open an nft port.
  - Can be assigned to a user, group and collection rule.
  - An admin or full-access rule cannot bypass it either.
- An entry referenced by a rule cannot be deleted or renamed.
- Two-line entry cards on the interface.

##### 3.6.0 – multiple root domains, HTTPS portal, visibility (deployed and committed: `62cdabc`)

- **Multiple root domains** (`proxy_domains`). The entry identifier is the full hostname (`name.root`).
- **Migration:**
  - The old `proxy_domain` becomes a list.
  - Short names of domain rules become full hostnames, with a backup.
  - Verified on the VM: `teszt-access` → `teszt1/2/3.<test-domain>`.
- **The Dropjak portal over HTTPS, on every root domain:** `https://<test-domain>`, with a Let's Encrypt certificate.
  - It accepts the `X-Forwarded-For` header only from loopback.
  - The session cookie gets the `Secure` flag.
  - `/api/proxy/*` is not reachable from outside, even through the proxy.
- **Visibility:** `private` (domain rule required) or `public` (anyone can open it).
- Push to GitHub: only with the `~/.ssh/id_claude_ed25519` key.

##### 3.7.0 – fail2ban proxy, certificates, logging, HTTPS redirect (deployed, not committed)

- **Fail2ban "proxy" category:**
  - X number of 401s within a time window triggers a ban. Default: 20 hits in 10 minutes.
  - The ban closes only 80/443, with the new `proxy_banned_v4` nft set. The :8100 portal remains reachable.
- **Domain settings** on the Settings tab:
  - switch for automatic certificate (`proxy_acme`);
  - uploading certificate and key per root domain (`certs/` in the state volume, 0600).
  - The key never appears on any API or in any log.
- **Log:** `proxy_page_opened` event, only on page load (based on `Sec-Fetch-*` headers).
- **Drop log:** proxy 401s appear as `proxy-unauthorized` lines. They do not count toward packet-based fail2ban signals.
- **HTTPS redirect:** from the WAN, from `http://…:8100` a 308 to `https://<first root>/`.
  - Exception: LAN, banned IP, `/api/`, loopback, or if there is no certificate.
- The `proxy_banned_v4` appears in the admin firewall view.
- **Deployment:**
  - New image: `6a1e9656bce9`. The previous one was kept as `hatarvedelem:prev-3.6.0`.
  - Backup: `hatarvedelem-20261021-210454.tar.gz`.
- **Verified from outside:**
  - :8100 redirects with 308;
  - `https://z2…` returns 200;
  - `teszt1` returns 401.
- **Also verified on the VM** (`recreate-20261021-210526.log`): Caddy runs with the new, `get_certificate` Caddyfile, the `proxy_banned_v4` set and the 80/443 drop rule are alive, the `.env` did not change.

##### 3.8.0 – challenge (deployed: 2026-10-22)

- **Per-entry expandable "Challenge (verification)" section, with checkboxes:**
  - On first open: 24-hour verification.
  - Every X hours: 1–720 hours.
  - On the first open each day: expires at local midnight.
  - If the IP has already received a 401: based on the fail2ban proxy counter.
  - If any fail2ban counter is running against it.
  - Suspicious client: missing browser headers, or curl/wget/script User-Agent.
  - From a new IP: verification is bound to the IP.
- **Challenge page:** the denial page's look with the `sus.png` image, below it an English-language captcha ("I'm not a robot", "Checking…", "Verified") as a PoW field or as Turnstile. There is no other button; apart from the image only the captcha is visible (no status icon).
  - It returns 403, not 401, so fail2ban does not count it, and it does not go into the drop log.
  - A failed solution does count, however.
- **Verification:**
  - Cookie: `__Host-dropjak_pass` (HMAC, Secure, HttpOnly).
  - Caddy strips it before the request reaches the upstream.
  - The key is generated randomly at process start, so verifications become invalid when the portal restarts.
- **Endpoints:** `/api/gate/challenge` (GET and POST), in the Caddyfile `/__dropjak/challenge` and `/__dropjak/sus.png`.
- **Tested:** end-to-end with real Caddy 2.10.2 and headless Chromium. 668 tests, all passed.

##### 3.8.0 further parts (deployed, 673 tests, all passed)

- **Unknown subdomain** (for example `ezbiztosnemletezik.z2…`): a challenge always comes, after success a redirect to `https://<test-domain>/`.
  - It works only with an uploaded wildcard certificate. For an unknown name the system never requests an ACME certificate (Let's Encrypt rate limit).
  - **There is no wildcard certificate in production** (there is no `certs/` directory on the VM), so `https://asd.z2…` gives a TLS error (`SSL_ERROR_INTERNAL_ERROR_ALERT`). There was a misunderstanding: the user had not uploaded a certificate.
  - The `*.z2…` wildcard is not valid for two-level names of the form `a.b.z2…`.
- **Logs:** IP filter (exact address or CIDR), filters on the server, matches the `ip`, `target`, `target_ip`, `session_ip` and `request_ip` fields. The proxy hostname and the path appear in bold at the beginning of the line.
- **Documentation:** the two DNS records as a prerequisite in the README and in the [local guide](#telepites).
- **"Daily" trigger:** `/etc/localtime` is mounted into the container read-only, so it switches at Hungarian midnight, not according to UTC.

---

##### 3.8.1 – HTTP redirect based on the Dropjak decision (deployed)

- On port 80, Caddy asks the `/api/proxy/redirect` endpoint via `forward_auth` where to redirect.
  - The root domain and existing entries receive a 308 to their own HTTPS address, the path is preserved.
  - If an unknown subdomain is covered by the uploaded wildcard certificate, it also receives a 308.
  - Every other unknown subdomain, the raw IP address and a foreign Host receive a 302 to `https://<root>/`.
- The ACME verification path is an exception, and if the portal is unreachable, Caddy gives the old redirect (`handle_errors`).
- Decision: for an unknown subdomain, a TLS error remains over HTTPS, because there is no wildcard certificate and we do not use Cloudflare. Dropjak-DNS (zone delegation and DNS-01) will come up again when replacing Cloudflare.
- Verified in production, all 9 cases are fine. New image: `e94d20677d0c`; the previous one was kept as `hatarvedelem:prev-3.8.0`. Backup: `hatarvedelem-20261021-221554.tar.gz`.
- Open question: the VM's system timezone is `Etc/UTC`, so the "Daily" trigger switches at UTC midnight.

##### 3.9.0 – "Many refreshes / spam" challenge condition (deployed)

- New checkbox (`burst`): if the same IP opens (refreshes) a page of the entry 10 times within 30 seconds, a new verification is required. A verification issued before detection does not count.
  - Only page opening counts, XHR and file requests do not. The counter is in the portal's memory, per IP+host.
- The new `sus.png` in production (md5 matches the local one).
- Verified in production, all 9 cases are fine. New image: `5a6a54c842a7`; the previous one was kept as `hatarvedelem:prev-3.8.1`. Backup: `hatarvedelem-20261021-223337.tar.gz`.

##### 3.9.1 – adjusting `sus.png` (deployed)

- On the challenge page the image was moved 8px to the left so that it aligns with the captcha.
- Verified in production, all 9 cases are fine. New image: `65f64fe9833e`; the previous one was kept as `hatarvedelem:prev-3.9.0`. Backup: `hatarvedelem-20261021-224148.tar.gz`.

##### 3.10.0 – the disabled automatic certificate actually disables (done locally, awaiting deployment)

- **Bug (in production, 3.9.1):** after disabling automatic certificate in Domain settings, Let's Encrypt certificates continued to be served, on every entry and on the root (in the Dropjak interface) as well.
- **User expectation:** "if someone doesn't want auto cert, then don't mess with the certs". In the disabled state only the uploaded certificate lives; where there is none, there is a TLS error.
- **Cause (verified from source, certmagic v0.24.0 = Caddy 2.10.2):**
  - `handshake.go` `getCertDuringHandshake`: the order is memory cache → `get_certificate` (uploaded) → `ask` → load from `/data` → new request. Before a cache hit, nothing asks `ask`.
  - Before loading from `/data`, `checkIfCertShouldBeObtained` calls `ask`; with the switch off this is 404, so nothing is loaded after a restart either. The bug therefore lived only in memory.
  - Caddy `modules/caddytls/tls.go` `Cleanup`: on reload it removes only statically managed (`managing`) and loaded (`loaded`) names from the cache, not on-demand certificates. So a reload does not help; a restart is needed.
- **Solution (smaller than the plan):**
  - The Caddyfile remained static; generated JSON and config push are not needed, because with the switch off `ask` already blocks every request and storage load.
  - The admin API lives only on a Unix socket: `admin unix//run/caddy-admin/admin.sock|0666`, on the `caddy-admin` volume mounted only into the two containers (directory `root:hatarvedelem 0750`, set by the portal entrypoint). No TCP port and no Docker socket.
  - When switching on→off, the portal's background thread sends `POST /stop`. Caddy exits with code 0, and `restart: unless-stopped` restarts it with an empty cache; Docker 26.1.5 `restartmanager` restarts under the unless-stopped rule regardless of exit code, with a 100 ms delay.
  - The request survives a portal restart in a flag file (`caddy-restart-pending`). With Caddy unreachable, it retries with 2–60 s backoff. It starts a restart once per request, never in a loop.
  - Besides ACME, certificate upload also restarts Caddy, so the uploaded certificate takes precedence over the in-memory ACME certificate.
  - `grace_period 5s`: shutdown waits at most 5 s for open connections.
  - Domain settings also show Caddy's status: reachable or not, last restart, restart in progress, error.
  - Nothing touches `/data`.
- **Local e2e (Pebble test CA, real `caddy:2.10.2-alpine`, podman, `/tmp/acmeoff-e2e/`):**
  1. ACME on: the root and two entries received a Pebble certificate (3 issuances); the uploaded wildcard went on the `z1` root, its entries and an unknown subdomain.
  2. The bug reproduced: with the socket hidden, disabling made `ask` return 404, but Caddy still served the cached Pebble certificates. The status at this point: "not reachable", in progress.
  3. After restoring the socket, Caddy restarted within 3 s (once). From then on, the handshake for ACME names is faulty ("decision func … 404"), the uploaded wildcard works.
  4. Through the normal path (with the socket reachable), 0.2 s after disabling the ACME certificate no longer worked on the root.
  5. Even after a manual Caddy restart it remained disabled.
  6. Switching back on, the same serial numbers came back ("loaded certificate from storage"), without a new issuance (Pebble: 3 → 3), and there was no Caddy restart either.
  7. Upload alongside ACME: the uploaded one was served instead of the in-memory Pebble certificate.
  8. The portal restarted via the flag file stopped Caddy once; after that only checks ran for 65 s, no further `/stop`.
  9. With the portal stopped, Caddy keeps running, but `ask`/`get_certificate` do not answer, so it serves nothing (fail-closed, as before).
  10. Still working: forward_auth (200 and 401), challenge page (403 + `sus.png`), stripping of the `__Host-dropjak_pass` cookie, the 80 redirect (308/302), `/api/proxy/*` 404 on the root, `/api/proxy/cert` cannot be fetched through Caddy.
  11. Socket permissions with the volume: group 999 could access it, uid 1000 got `Permission denied`. Caddy (root, without `DAC_OVERRIDE`) created the socket and recreated it on restart as well.
- **On deployment:**
  - A new `caddy-admin` volume is created.
  - Both containers restart: because of the modified configuration, compose recreates Caddy too, and this also clears the current, stale cache.

##### 3.11.0 – Proxy tab: TCP/UDP port proxy (deployed 2026-10-22, commit `c18ae93`)

- **User request:** a Proxy tab similar to the Domains tab, where a reverse proxy can be configured in both input and forward directions. For example, traffic arriving on port 25565, if the client's rule allows it, goes to the specified IP (forward) or to this host (input). Both TCP and UDP are needed, because of Minecraft Simple Voice Chat (UDP 24454); it worked with socat, not with rinetd (classic rinetd is TCP-only).
- **Decision: kernel-level DNAT (nftables), not a userland proxy.** The client IP is preserved, UDP works with conntrack, there is no separate process, and the existing authorization sets (`allowed_tcp/udp`, `allowed_input_tcp/udp`) can be used.
- **Data model:** `port_proxies` list in `firewall-settings.json` (at most 64). Fields: `id`, `label`, `proto` (`tcp`/`udp`/`both`), `listen_port`, `type` (`input`/`forward`), `target_ip` (forward only, 10/8, 172.16/12, 192.168/16), `target_port`, `ifaces` (`wan`/`lan`/`both`), `snat` (forward only), `enabled`. An old file without the key gives an empty list.
  - Reserved listening ports: 22, 53, 67, 80, 443, 2019 and the portal port.
  - The (protocol, listening port) pair is unique; `both` reserves both TCP and UDP, even for a disabled entry.
  - Input target port cannot be 22 (SSH can only be opened with an explicit TCP 22 host rule), 2019 and the portal port.
  - For an input entry, the target port cannot be the same as the listening port: such a redirect does nothing, and a host rule alone opens the same thing. Therefore we reject it.
- **nft chains** (filled by the portal, template reload does not clear them):
  - `portproxy_prerouting`: its own `type nat hook prerouting priority -101` chain, only `jump portproxy_nat`.
  - `portproxy_nat`: for forward `dnat ip to <target>:<port>`, for input `redirect to :<port>`. Only for traffic addressed to the host (`fib daddr type local`), on the selected interfaces; thus a LAN client's traffic to an external server on the same port remains untouched.
  - `portproxy_input`: jumped to from the input chain, after the fail2ban drop, the block, the MAC check and the proxy ban, but before the 80/443 proxy accept, the host guards and the established accept. Authorization: (client IP, ORIGINAL listening port) in the `allowed_input_*` set (`ct original proto-dst`), because after the redirect the packet's destination port is already the target port. A non-authorized packet is logged and dropped (`reason=portproxy`), per packet, so revocation also cuts the open connection.
  - `portproxy_snat`: the first jump of postrouting; masquerades only the flow of the requested forward entry.
  - No new rule was needed for forward: the forward chain's existing `ct original ip saddr . ct original proto-dst @allowed_tcp/udp` rule (with FWD_MARK) allows it, just like Docker-published ports.
- **Example** (Minecraft forward from the WAN, Voice Chat input from the LAN):

  ```
  add rule inet hatarvedelem portproxy_nat iifname "eth0" fib daddr type local tcp dport 25565 dnat ip to 192.168.10.20:25565
  add rule inet hatarvedelem portproxy_nat iifname "eth1" fib daddr type local udp dport 24455 redirect to :24454
  add rule inet hatarvedelem portproxy_input iifname "eth1" meta l4proto udp ct status dnat ct original proto-dst 24455 ip saddr . ct original proto-dst @allowed_input_udp ip saddr . ether saddr != @client_mac limit rate 30/minute burst 60 packets log prefix "dropjak-drop reason=mac " group 5
  add rule inet hatarvedelem portproxy_input iifname "eth1" meta l4proto udp ct status dnat ct original proto-dst 24455 ip saddr . ct original proto-dst @allowed_input_udp ip saddr . ether saddr != @client_mac drop
  add rule inet hatarvedelem portproxy_input meta l4proto udp ct status dnat ct original proto-dst 24455 ip saddr . ct original proto-dst @allowed_input_udp accept
  add rule inet hatarvedelem portproxy_input meta l4proto udp ct status dnat ct original proto-dst 24455 limit rate 30/minute burst 60 packets log prefix "dropjak-drop reason=portproxy " group 5
  add rule inet hatarvedelem portproxy_input meta l4proto udp ct status dnat ct original proto-dst 24455 drop
  ```
- **Docker DNAT precedence:** Docker's `ip nat PREROUTING` has priority -100, the same as our `prerouting` chain; with the same priority the order depends on registration order. The kernel (`nf_nat_inet_fn`) calls nat chains by priority, and after the first NAT binding it does not run the rest. The -101 chain therefore deterministically wins: on the configured interfaces the Proxy entry precedes Docker's publishing of the same port. We do not ban such a port, only warn (in the save response and on the interface), likewise if a local socket is already listening on the port (`/proc/net/tcp*`, `udp*`, and the `ip nat DOCKER` chain).
- **Side fix (MAC check of the forward chain):** the LAN MAC check of port authorizations examined the IP+MAC pair in the response direction too. The response of a DNAT target on the LAN arrives on the LAN interface with the target's own IP/MAC pair, so it was dropped (`reason=mac`). Now it only looks at the original direction (`ct direction original`).
- **Saving:** the `port_proxies` operation of `_admin_settings_action` (admin, origin, lock). `apply_settings` swaps the proxy chains in one transaction with the pre-auth and block chains, then writes the file, restores on error. conntrack entries of changed, new or deleted listening ports are deleted (`conntrack -D -p <proto> --orig-port-dst <port>`). Audit: `admin_portproxy_changed` with a summary of the entries. At startup `_apply_custom_settings` loads it; with a bad settings file the proxy chains are empty (fail-closed).
- **Interface:** Proxy tab next to Domains, a two-line card per entry (line 1: label, active, delete; line 2: protocol, listening port, type, target IP, target port, interface, SNAT). Collapsible help with the Minecraft and Voice Chat example (on the server `port=24454`, for a different public port `voice_host=<public name>:<listening port>`). HU/EN/DE.
- **Tests:** 721 tests, all passed (`tests/test_port_proxy.py`: store validation, exact nft lines, template order, `unshare -rn nft -c`, apply/rollback; admin API tests in `test_gateway.py`).
- **Local packet-level trial** (user namespace, veth pairs, not part of the test suite): forward TCP/UDP passed with authorization, the target saw the client IP, the fake -100 "Docker" DNAT did not take effect; with SNAT the target saw the router's address. Input passed only with authorization given to the listening port (not with authorization given to the target port). Without authorization, from a banned IP and after revocation it was dropped. This trial brought out the MAC bug above.

##### 3.11.1 – Input port proxy to a target listening only on 127.0.0.1 (fix)

- **Bug report:** the `<test-domain>:8084` → 8081 (Input, TCP, WAN) entry did not work. On 8081 runs the `teszt1` nginx, which Docker publishes ONLY on `127.0.0.1:8081`.
- **Live diagnosis (on the VM, read-only):**
  - The entry was stored correctly, the nft rule was `iifname "eth0" fib daddr type local tcp dport 8084 redirect to :8081`.
  - The user's IP (`<client IP>`) had authorization: `allowed_input_tcp` contained the `<client IP> . 8084` pair. Authorization was therefore fine.
  - `nft monitor trace` with a temporary, narrow (tcp dport 8084) trace table: the SYN was rewritten by `portproxy_nat`, accepted by `portproxy_input`, and the host sent `RST|ACK` from `<test-vm>:8081`. The conntrack reply tuple: `src=<test-vm> sport=8081`.
  - `redirect` rewrites to the primary address of the incoming interface (WAN IP). Nothing listens there: docker-proxy only on `127.0.0.1:8081`, and Docker's DNAT also matches only `ip daddr 127.0.0.1` (after the -101 NAT binding Docker's -100 NAT does not run anyway). Hence "Connection refused".
  - Earlier tests did not catch this: in the local packet trial the target listened on every address.
- **Fix:**
  - If ALL sockets on the target port are bound to 127.0.0.0/8, the rule is `dnat ip to 127.0.0.1:<target port>`. This applies to both TCP and UDP; the decision is made based on `/proc/net/{tcp,udp}{,6}`. For a wildcard listener, `redirect` remains: the "naive" wildcard UDP server (Java/Simple Voice Chat, docker-proxy) chooses the response source from the route, which would not match conntrack with 127.0.0.1 DNAT.
  - For a 127.0.0.1 target, `net.ipv4.conf.all.route_localnet = 1` is needed on the host. In the portal container `/proc/sys` is read-only (Docker ReadonlyPaths), so `docker/setup-host.sh` sets it in `/etc/sysctl.d/90-dropjak.conf`. If it is not enabled, the proxy remains `redirect`, and saving warns.
  - **Security:** a new `loopback_guard` chain (prerouting, raw priority, before NAT) in both the main and boot tables: every packet with a 127/8 destination or source arriving on a non-loopback interface is dropped. The loopback service is thus reachable only through the authorized proxy DNAT. As a side effect, Docker's 127.0.0.1 publications cannot be targeted directly from the LAN either (the equivalent of Docker 28+ raw rules; Docker 26 runs on the VM).
  - **Refresher:** the portal recalculates the decision every 10 seconds. If it changed (for example, after a restart Docker publishes later, or route_localnet was enabled), it atomically swaps the chains and deletes the conntrack entries of the affected listening ports. Settings save and the refresher use the same lock.
  - **Client IP:** it is preserved for a native service bound to loopback. For a Docker container, through the 127.0.0.1 publication the container sees the docker-proxy address. If the client IP is needed, use a Forward entry to the container IP.
- **Tests:** 728, all passed.
  - New unit tests: loopback detection (v4, v4-mapped v6, wildcard, ::1), route_localnet, rule selection, warning, refresher, template and boot guard.
  - `tests/test_portproxy_netns.py`: packet-level test without root (`unshare -rn`). WAN and LAN client, TCP/UDP, input and forward, targets bound only to 127.0.0.1. Blocked before authorization, after it the content and client IP are correct, blocked after revocation. The old `redirect` bug is reproduced as RST, and a forged raw frame to a 127.0.0.1 target is accepted by the server only without the guard.
  - Live VM test: `tests/portproxy_e2e_vm.py`.
- **For the user's 8084 entry**, after the fix nothing else is needed but to select the host (input) rule allowing 8084 in the session (this was already there).

#### Important decisions

- **Cloudflare cannot be in the chain.** Dropjak replaces Cloudflare in the user's stack, so neither Cloudflare API nor Cloudflare proxy.
- **Unknown subdomain:** TLS error over HTTPS (no wildcard), redirect to the root over HTTP (3.8.1). The challenge branch remains in the code and works immediately with an uploaded wildcard certificate.
- **Wildcard automation later:** Dropjak will be its own DNS server for the delegated zone (NS + glue at the registrar), and request certificates with DNS-01. It will come up when the full Cloudflare replacement becomes current.
- **Access:** a domain rule is required, no admin and full-access exception; public entries do not require login.
- **`HV_PORTAL_URL` unchanged,** because the LAN captive portal remains on HTTP.

#### Test infrastructure on the VM

- `/root/nginx-teszt/`: three nginx containers, reachable only on 127.0.0.1.

  | Container | Port | Content |
  |---|---|---|
  | teszt1 | 8081 | blue page, with an `/info.html` subpage |
  | teszt2 | 8082 | green page |
  | teszt3 | 8083 | orange page |

- Live entries: `teszt1`, `teszt2` and `teszt3` under `<test-domain>`.
- Domain rule: `teszt-access`, which is also a member of the `mpwerks` collection rule.

#### Backups and restore (VM, `/root/hatarvedelem-backups/`)

| Before version | Backup | Previous image tag |
|---|---|---|
| 3.4.0 | `hatarvedelem-20261021-165039.tar.gz`, `env-20261021-165049.bak` | `prev-3.3.0` |
| 3.5.0 | `hatarvedelem-20261021-190830.tar.gz` | `prev-3.4.0` |
| 3.6.0 | `hatarvedelem-20261021-195157.tar.gz`, `pre-3.6.0-20261021-195057/` | `prev-3.5.0` |
| 3.7.0 | `hatarvedelem-20261021-210454.tar.gz` | `prev-3.6.0` |
| 3.8.0 | `hatarvedelem-20261021-215908.tar.gz` | `prev-3.7.0` |
| 3.8.1 | `hatarvedelem-20261021-221554.tar.gz` | `prev-3.8.0` |
| 3.9.0 | `hatarvedelem-20261021-223337.tar.gz` | `prev-3.8.1` |
| 3.9.1 | `hatarvedelem-20261021-224148.tar.gz` | `prev-3.9.0` |

**Restore:**

```sh
docker tag dropjak:prev-X dropjak:2
docker compose up -d --force-recreate
```

If necessary, restoring the state archive is also needed.

#### Known limitations and risks

- **IP-based identification:** those behind the same public IP (NAT, CGNAT) share the entitlement. Recommended next step: cookie-based identification.
- **Already open connections:** WebSocket and streaming connections remain alive after revocation.
- **Exposed surface:** Caddy and the portal are an attack surface available to everyone. Packet-based fail2ban does not see 80/443 attempts; the proxy category counts them.
- **Directly reachable upstream:** if an upstream listens not only on 127.0.0.1 and a port rule opens it, the domain rule can be bypassed.
- **Forward target:** it does not block the firewall's own LAN address.
- **Port proxy forward target is the firewall's own address:** we do not block it; in this case the packet enters the input chain, and would only pass with a host authorization given to the target port. The Input type is for this.
- **Port proxy and drop-based fail2ban:** the `reason=portproxy` drop counts toward the ban, like `no-grant`; a game client that tries a lot without logging in can thus be banned.
- **IPv4 only:** IPv6 inbound traffic is dropped, so there can be no AAAA record.
- **LAN:** before login, LAN clients cannot reach 443, so for them the HTTP captive portal remains.
- **Fail2ban-banned IP:** it sees the denial page only on :8100, not on the HTTPS portal.
- **Non-browser clients** (API, webhook, CLI): with challenge checkboxes enabled they receive 403.
- **Certificate cache (handled since 3.10.0):** disabling ACME and uploading alongside ACME restarts Caddy (at most a few seconds of outage, open connections are cut). If Caddy is just requesting a certificate, the restart may interrupt it, and the next handshake requests it again (a wasted issuance). Without a restart policy, Caddy would remain stopped after `/stop`.

#### To-dos

- [x] Deployment of 3.8.0. New image: `40a2802222c5`; the previous one was kept as `hatarvedelem:prev-3.7.0`. Backup: `hatarvedelem-20261021-215908.tar.gz`.
- [x] Verification of 3.8.0 on the VM: the Caddyfile is fine, the `.env` did not change.
- [x] 3.10.0: fix of the disabled automatic certificate and the Pebble test.
- [ ] Deployment of 3.10.0 (approved; SSH needed).
- [ ] Decision on the VM timezone (`Europe/Budapest`?). The VM is `Etc/UTC`, the container sees the machine's time.
- [ ] Live trial of the 3.9.0 "spam" checkbox and the 3.9.1 image adjustment on an entry with a checkbox.
- [ ] Deployment and live trial of 3.11.0 (Proxy tab) with Minecraft + Simple Voice Chat.
- [ ] Committing and pushing 3.7.0–3.9.1.
- [x] Verification of the 3.7.0 `recreate` log on the VM.
- [ ] The unused `Unauthorized Wojak Prohibition Emblem.png` can be deleted from the VM project folder.
- [ ] Optional: cookie-based proxy identification, upstream binding check, live test of Turnstile.

<a id="biztonsagi-atvizsgalas"></a>

## 5. Security review (2026-10-21)

_Source: `docs/security-review-2026-10-21.md` (original title: "Dropjak / border protection — security report")._

**Date:** 2026-10-21
**Method:** static code review (`server.py`, `gateway.py`, `fail2ban.py`,
`settings_store.py`, `deploy/dropjak.nft`, `docker/entrypoint.sh`,
`index.html`). Did not touch a live VM, did not run tests.
**Status:** report only; did not modify any code.

### Overall picture

The system is well hardened. The classic intrusion paths are closed:
there is no shell injection, no nft injection, no path traversal, no XSS, and
the auth layer is timing- and replay-protected. The points found are not
code bugs, but deployment and residual risks — but the first of these is real and serious in the current live configuration.

### Findings ranked

#### 1. HIGH — Unencrypted HTTP toward the open internet

The main risk is not in the code, but in the way it is run. The live configuration
`HV_PORTAL_NET=0.0.0.0/0` (portal to the entire internet), the default of `HV_COOKIE_SECURE`
is `0`, and there is no TLS (`gateway.py:265`). Thus the **password, the TOTP code, the
recovery code and the session cookie all travel in the clear, unencrypted** over the
WAN. Anyone on the path (upstream provider, data center, same
segment) can capture the credentials.

- Mitigating fact: the session is bound to an IP (`gateway.py:6353`), so a
  stolen cookie cannot be used from another IP. But whoever captures the *password + TOTP code*,
  or sits on the same IP / behind NAT, logs in completely.
- The [4.1 Domain proxy plan](#caddy-proxy-terv) already knows this (deferred). At report level this is
  the most important item.
- **Interim mitigation:** narrow `HV_PORTAL_NET` to a management CIDR,
  or put TLS termination in front before it remains reachable from the WAN.

#### 2. MEDIUM — MAC anti-spoofing protects only LAN sources

`binds_mac()` returns `True` only for IPs within `HV_LAN_NET`
(`gateway.py:3045-3052`). **Every source outside the LAN** (i.e. all WAN clients
because of 0.0.0.0/0) receives a grant **without** MAC binding, and the forward
port-accept and input host-accept rules have no `iifname` binding
(`deploy/dropjak.nft:245-250, 444-445`). So the "5.1.4 MAC binding on the LAN" invariant is in practice true only for LAN sources. Within the LAN
an active attacker can clone both the IP and the MAC from the same
L2 segment.

**Consequence:** do not regard MAC binding as an access boundary — it only raises the bar against passive
IP reuse (DHCP change). The documentation acknowledges
that "MAC ≠ authentication"; this point concretizes how narrow the protection is.

#### 3. MEDIUM / LOW — IP-based identity + carrier-NAT collision

The session is one per IP, and fail2ban bans by source IP. With
0.0.0.0/0 exposure, for clients behind carrier NAT (many users →
one public IP):

- one user's login kicks out another's;
- **a single malicious user can ban the entire group behind the NAT**
  (DoS), and `on_ban` also terminates other users' sessions.

An inherent consequence of IP-based gating. If WAN exposure remains, a shorter
ban time and a higher threshold are worthwhile.

#### 4. LOW — No global cap on pending registrations

With `registration_enabled=true`, the limit is 3/10 minutes per source IP
(`server.py:1579`), but there is **no limit on the total number of pending accounts**. Over time,
or from many IPs, `users.json` grows without bound; it is loaded and
validated on every start, slowing startup and the admin Users tab. Proposal:
a max-pending cap and/or expiry of unapproved requests.

### What was checked and is fine (not a finding)

- **nft calls:** argv list, no `shell=True` (`gateway.py:2724`); only ports validated as `int` and target addresses
  canonicalized with `ipaddress` go into the `nft -f -` script (`_custom_dst`, `_custom_ports`) —
  newline/syntax injection is not possible.
- **entrypoint:** every placeholder env is validated before rendering (ifname
  charset, CIDR with Python, numeric port/group, hex mark) —
  `docker/entrypoint.sh:134-144`.
- **Password:** PBKDF2-HMAC-SHA256 600k iterations + dummy-digest timing protection
  (`gateway.py:4844`).
- **TOTP:** constant-time, replay-protected with `totp_last_step`, under lock
  (`gateway.py:5204-5236`); recovery code constant-time, single-use.
- **PoW captcha:** HMAC-signed (difficulty cannot be reduced), replay-protected
  (`gateway.py:6982`). Weak by design; the real brute-force barrier is fail2ban.
- **Authorization:** `resolve_for` allows only the rule assigned to the user
  (`gateway.py:2069-2081`); the admin guard checks the fresh
  user record on every request (`server.py:600`).
- **Session:** bound to IP, immediately revoked on IP change
  (`gateway.py:6353`); the client IP comes from the socket peer, not from
  `X-Forwarded-For` (`server.py:435`).
- **nft logic:** the forward chain has no general `established accept`
  bypass; revocation cuts immediately through the `ct original` match; the input
  chain's guard rules (SSH/22, DNS/53, host_service_*) consistently close
  orphaned flows.
- **UI:** all user data is rendered with `textContent`; the only
  dynamic `innerHTML` path receives only internal icon SVG — no stored XSS. The
  admin-state does not leak secrets (hash/secret/recovery omitted,
  `gateway.py:4690-4700`).

### What was not examined

- Did not run the 563 tests, and did not test on a live VM (the project rule
  forbids loading the firewall on a development machine) — the nft findings come from a static reading of the template,
  not verified by kernel measurement.
- Only superficially looked at the `droplog.py` netlink parser and the internal counters of `fail2ban.py`.

### Final risk assessment

#1 (unencrypted HTTP on the WAN) is real in the current live configuration, not
theoretical — this is the most important task. #2–#3 are exacerbated by the 0.0.0.0/0 exposure;
narrowing `HV_PORTAL_NET` mitigates all three at once.

<a id="tervek-archivum"></a>
## 6. Plans and archive

<a id="antislop-terv"></a>

### 6.1 Anti-slop plan (2026-10-20)

_Source: `docs/antislop-terv-2026-10-20.md` (original title: “Anti-slop plan — Dropjak portal (2026-10-20)”)._

Status: implementation of the P0 round is in progress. The audit was prepared against the state of commit `267a1ce`.
The pre-de-slop design backup: `docs/design-backup-2026-10-20/`, tag: `design/pre-deslop-2026-10-20`.

#### Starting point

The portal's foundation is not slop: the login's voice (“Stop!”, “Identify yourself!”), the serif wordmark, the
two-phase captive-portal flow, the real empty/loading/error states, the tables and the HU/EN/DE i18n
remain. The slop is concentrated in the admin **Drop log** and **Fail2ban** dashboards, the microtypography and the
pill system.

Measured numbers in the initial state:

- 151 different hex colors in the stylesheet, while `:root` defines 20 semantic tokens.
- 21 font-size values; 72 declarations below 12px; 6 wide-tracked uppercase labels.
- 12 border-radius values, 8 decorative gradients, 21 box-shadows.
- 10 pill variants; in the drop table every row gets a `reason-pill`.
- 21 hardcoded accent colors in the JS; the dark-mode chart red has 2.67:1 contrast.
- Input border `--line-strong:#d6d6d2` on white 1.46:1; `#8a8a85` text 3.47:1; `#9a9a95` 2.83:1.

#### P0 — CSS-only quick wins (this current round)

Goal: remove the most visible slop without admin flow, API, table or string changes.

1. **Normalizing the type scale and text below 12px.** `--fs-2xs:12px`, `--fs-xs:12.5px`,
   `--fs-sm:13px`, `--fs-md:14px`, `--fs-lg:16px`, `--fs-xl:20px`; replacing the 9–11.5px
   declarations (the chart axis may remain 11px). The 6 uppercase labels (`th`, `.ban-label`, `.role-pill`,
   `.stat span`, `.drop-stat > span`, `.drop-filter-field label`) switch to sentence case.
2. **Flat surfaces.** Instead of the drop/fail2ban gradients, `var(--soft)` / `var(--card)`; removing the 3px
   decorative left bars (`.drop-stat::before`, `.drop-card-head h3::before`,
   `.drop-filter-head b::before`) and the `.drop-dot` glow; removing the tab/nav active shadows.
   The card (`:63`) and the language menu (`:205`) elevation remain.
3. **Contrast and focus ring.** `--muted-strong:#6b6b66`; replacing `#8a8a85`, `#9a9a95`, `#a6a6a0`;
   global `:focus-visible{outline:2px solid var(--blue);outline-offset:2px}`; removing
   `outline:none` from the inputs, the `.lang-option` and the `.picker-search`.
4. **Cutting back the pill forest.** The in-table `.pill`, `.reason-pill`, `.role-pill`,
   `.drop-filter-count`, `.fw-verdict`, `.fw-legend span` become plain text + a colored dot; the `.chip`
   gets 4px radius, 12px font; the `.status-pill` remains the only page-level badge (12.5px).
5. **Fail2ban stat grid.** `.drop-stats` `repeat(auto-fit,minmax(150px,1fr))`, so the fifth
   card does not hang alone.
6. **Removing the Captcha “HV / verification” brand.** Deleting the `.captcha-brand` CSS and markup.
7. **Tap targets and iOS zoom.** `.theme-toggle` 40px (44px on coarse pointers); `button.small`,
   `td.actions button` `min-height:32px` (44px on coarse pointers); on mobile the inputs are 16px.

#### P1 — next round (not yet implemented)

- Replacing the stat wall (Drop: 1–2 real metrics + status line; Fail2ban: status + banned IPs).
- Semantic palette: the 21 hardcoded accents to tokens; max. 2–3 base colors + accent.
- Theme-aware chart: CSS token for the fill, 3:1 segment contrast, time window in the title.
- Empty state differentiation: first run vs. “no matches for the filter” + clear-filter action.
- Long help texts progressive disclosure (`<details>`), shortened copy.
- ARIA: rule card `aria-pressed`/radio semantics, accessible name for empty `<th>`, tablist/tabpanel.
- Naming: unifying the “Settings” tab vs. the “Firewall customization” heading; “Repeat new password”.
- Field boundary token (3:1), a full 44x44 tap target pass, a 200% zoom test.

#### P2 — larger redesign (later)

- Full token system (color, type, spacing, radius, elevation, chart palette) + `docs/design-direction.md`.
- Drop log decision-first redesign; Fail2ban redesign; simplifying the firewall visual view.
- Grouping admin navigation; identity refinement.

#### What must not change

- The serif “dropjak” wordmark and the diamond-line motif.
- The HU/EN/DE architecture (`data-i18n`, `tr()`, dictionaries, flag language switcher).
- The light/dark token pair and the toggle that follows the system preference.
- The two-phase captive-portal flow and the fail-closed messages.
- The ban screen's Wojak illustration and the “Stop!” voice.
- The structure of the rule cards, the tables + sticky header + mobile horizontal scroll strategy.
- The real empty/loading/error states, the live countdowns, the semantic status colors.
- The use of monospace for IP, timestamp, ports and nft rule.
- The existing concrete copy (no hype, fake statistics, emoji).

#### Acceptance checklist for the P0 round

- Login, ban, access, session, password views at 360, 390, 768, 1024, 1440px; no page-level
  horizontal scroll; the tables scroll within their own wrapper.
- After a HU/EN/DE language switch, every static and dynamic label is correct.
- Light and dark theme; the focus ring is visible on every interactive element, at least 3:1.
- Keyboard: Tab on the login, captcha Enter/Space, rule cards, TTL, buttons, admin nav, forms;
  Escape in the language menu; no focus trap.
- All admin tabs: Users, Groups, Rules, Sessions, Firewall, Drops, Fail2ban, Logs, Settings.
- No console errors; the network request payload is unchanged.
- Contrast spot check: 12px text 4.5:1, border/focus/chart 3:1.
- 200% zoom at 390px; nothing slides over anything else.
- `python3 -m unittest discover -s tests -p 'test_*.py'` green (169 tests).

<a id="design-backup-notes"></a>

### 6.2 Design snapshot: notes

_Source: `docs/design-backup-2026-10-20/NOTES.md` (original title: “Design snapshot – 2026-10-20”). The content of the snapshot `README.md` listed in the table was moved to section [6.3](#design-backup-readme); the other files in the folder (`index.html`, `icon.png`, `blocked.png`, `screenshots/`, `SHA256SUMS`) remained in place._

**Date:** 2026-10-20
**Commit:** `267a1ce` – “Fix manual fail2ban ban visibility and admin session races"
**Status:** the version running in production (deployed) when the snapshot was made

#### Purpose

A pre-de-slop design snapshot / restore point. The goal is that the UI state before the visual redesign can be restored exactly.

#### Contents

| File | Size |
| --- | --- |
| `index.html` | 327,022 bytes (approx. 319.4 KiB) |
| `icon.png` | 122,957 bytes (approx. 120.1 KiB) |
| `blocked.png` | 1,346,593 bytes (approx. 1.28 MiB) |
| `README.md` | 14,849 bytes (approx. 14.5 KiB) |

The `index.html` references the `icon.png` and `blocked.png` files via relative paths, so the three files must remain in one folder.

The screenshots are in the `screenshots/` folder (login page only, in a signed-out state).

The snapshot contains only the UI files: `server.py`, the tests, the state files and the secrets (`.env`, `.secret`) were intentionally left out.

#### Restore

From the repository root:

```bash
cp docs/design-backup-2026-10-20/index.html index.html
cp docs/design-backup-2026-10-20/icon.png icon.png
cp docs/design-backup-2026-10-20/blocked.png blocked.png
```

Or using the design branch:

```bash
git checkout design/pre-deslop-2026-10-20 -- index.html icon.png blocked.png
```

Integrity can be checked with the `SHA256SUMS` file:

```bash
cd docs/design-backup-2026-10-20
sha256sum -c SHA256SUMS
```

<a id="design-backup-readme"></a>

### 6.3 Design snapshot: README copy

_Source: `docs/design-backup-2026-10-20/README.md` (original title: “dropjak”). Its line was deleted from the `SHA256SUMS` file at merge time (`a434271f59dc58994dd922bb922924f9d60e8e99e6f9fbe347f8a0b43cf64913  README.md`); the image path was adjusted to the repository root._

<p align="center">
  <img src="docs/design-backup-2026-10-20/icon.png" alt="dropjak" width="180">
</p>


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

#### How it works

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

#### Requirements

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

#### Docker installation

##### 1. Clone the repository

```bash
git clone https://github.com/moodpatcher/dropjak.git
cd dropjak
```

##### 2. Configure

Do this **before** the firewall is loaded: the first start closes host SSH, and
the only way back in is the portal. Without an admin account the portal's admin
interface is unreachable, so the password must be in `.env` before step 4.

```bash
./configure.sh
```

The script asks for the LAN and WAN interfaces (it lists them with their
addresses), the LAN network, the portal source network, the management
network, the portal port and the first admin account, then writes `.env`
with mode 0600. Press Enter to accept the offered default. The portal is
public by default (`HV_PORTAL_NET=0.0.0.0/0`); narrow it if it should not be
reachable from the internet. Leave the admin password empty to generate one.
Re-running the script preserves the current values as defaults and backs up
the old file.

Required values:

| Variable | Example | Meaning |
|---|---|---|
| `HV_LAN_IF` | `eth1` | interface facing the clients |
| `HV_WAN_IF` | `eth0` | interface facing the internet |
| `HV_LAN_NET` | `192.168.10.0/24` | client network in CIDR form |
| `HV_PORTAL_NET` | `0.0.0.0/0` | source networks allowed to reach the portal |
| `HV_ADMIN_ENABLED` / `HV_ADMIN_USER` / `HV_ADMIN_PASSWORD` | `1` / `admin` / a long random password | first admin, created or updated at container start |

If `HV_PORTAL_NET` is unset or empty, the portal is public (`0.0.0.0/0`). The
portal is always reachable from the LAN interface. Set it to a management
CIDR if the portal must not be reachable from the internet.

Find interface names with `ip -br link`. All other settings are documented in
`.env.example`.

##### 3. Prepare the host

Docker starts late in the boot process. To keep forwarded traffic blocked
until then, install the early boot guard:

```bash
sudo ./docker/setup-host.sh
```

The script installs `nftables` if needed, loads a boot-time `forward` chain
with `policy drop`, installs the `dropjak-boot.service` unit, and
persists `net.ipv4.ip_forward=1` in
`/etc/sysctl.d/90-dropjak.conf`.

The boot protection also drops inbound TCP 22. The script keeps the SSH
session that started it reachable (a single accept rule for that source
address) until the container loads its rules; every other source is blocked
immediately.

##### 4. Build and start

The build runs on the host network; the fail-closed forward chain blocks the
build container's egress, so apt-get cannot reach the Debian mirrors from
Compose's bridge (see 10.2).

```bash
DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .
docker compose up -d
docker compose ps
docker compose logs -f dropjak
```

Open the portal in a browser:

```
http://<lan-ip>:8100/
```

HTTP traffic from unauthenticated clients on port 80 is redirected to the
portal. The health check polls `/api/status`. The first start closes host SSH
(and every later recreate flushes the grants), so after this step the portal is
the way back in.

##### 5. First login and host SSH

The admin from `.env` is created (or its password updated) on container start.
Sign in at `http://<lan-ip>:8100/`, change the initial password, then create a
**Host SSH** (input, TCP 22) rule, assign it to the admin, and authorize it
from the same IP if you need SSH.

The **Admin** tab then provides user, group, rule and audit-log management.

A user can also be added from the CLI:

```bash
printf '%s\n' '<password>' | docker compose run --rm -T dropjak \
  python3 /opt/hatarvedelem/server.py user add alice --password-stdin
```

CLI-created users get the `user` role; promote them in **Admin → Users**.

#### Operations

##### Update

`update.sh` backs up the configuration and the state outside the checkout,
then runs a fast-forward-only pull (see 10.8); rebuild afterwards:

```bash
sudo ./update.sh
DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .
docker compose up -d --force-recreate
```

The entry point reloads the firewall rules idempotently. On portal start the
dynamic sets are flushed (`HV_FLUSH_ON_START=1`), so every user has to sign in
again. State in the Docker volume is preserved.

##### Status and logs

```bash
docker compose ps
docker compose logs -f dropjak
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
docker compose exec dropjak python3 /opt/hatarvedelem/server.py fail2ban list
docker compose exec dropjak python3 /opt/hatarvedelem/server.py fail2ban unban 203.0.113.10
docker compose exec dropjak python3 /opt/hatarvedelem/server.py fail2ban unban-all
```

Run these as root (the default for `docker compose exec`); the ban/unban
commands call `nft` and need `NET_ADMIN`. The running portal reloads
`fail2ban.json` when it changes, so CLI changes appear in the admin UI within
a few seconds without a restart.

##### Firewall customization

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

##### Backup

State is stored in the `dropjak-state` volume
(`/var/lib/hatarvedelem`): `users.json`, `groups.json`, `rules.json`,
`audit.jsonl`, `drops.jsonl`, `fail2ban.json` and `firewall-settings.json`.

```bash
docker volume ls | grep dropjak-state

docker run --rm -v dropjak-state:/data -v "$PWD":/backup \
  busybox tar czf /backup/dropjak-state.tar.gz -C /data .
```

The compose file pins the volume name to `dropjak-state`. `docker compose down -v`
deletes the volume; without `-v` it is kept.

#### Security notes

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

<a id="valtozasnaplo"></a>

<a id="portal-domain"></a>

### 4.3 The Dropjak interface's own address

By default, the root domains (`https://z1.example.com/`) serve the
Dropjak web interface. With the **Settings → Domain settings → Dropjak web
address** field, the interface can be moved to its own Caddy address, which
must be under a root domain (e.g. `dropjak.z1.example.com`). Caddy requests
an on-demand certificate for the address in the same way as for any other
name (or the root domain's uploaded certificate covers it).

When enabled:

- the interface is available only at its own address;
- the root domains are no longer the portal's: without an entry they do not
  redirect to the portal and have no certificate (404 on port 80). A root can
  host its own service: on the **Domains** tab, leave the subdomain field
  empty for an entry; the full hostname is then the root domain itself, and
  the entry works in the usual way (Input/Forward, port, visibility,
  challenge). Such an entry can only be saved with an active own portal
  address, and while it exists the portal address cannot be turned off;
- unknown names not covered by a certificate redirect to the portal on
  port 80;
- the address appears as an entry on the **Admin → Domains** tab among the
  proxy entries. Its address, type (Input), port and visibility (Public) are
  required for operation, so they are not editable; the entry has no Delete
  button. Only **Challenge** can be set on it; the portal's requests are
  enforced by the same `forward_auth` chain;
- disabling is possible only in Settings (empty address); the entry and its
  challenge are then deleted, and the root domains serve the portal again.
  With an entry for the root, disabling is rejected: it must be deleted
  first.

Saving checks that the address is under a root domain and does not collide
with an existing proxy entry. While the own address is active, the parent
root domain cannot be deleted. On the own address, the `/api/proxy/*`
endpoints—like on the root domain—are not reachable through Caddy, because
Caddy forwards to the portal and the socket peer there would be loopback.
The one exception is `/api/proxy/bind`, the portal hop of the private-entry
session binding (see 8.5), which checks the session cookie itself.

---

## 7. Changelog

_Source: `CHANGELOG.md` (original title: “Changelog”)._

All notable changes to Dropjak are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The running version is stored in [`VERSION`](VERSION).

> Entries before 2.9.0 were reconstructed retroactively from git history and
> the documentation in this repository. Version tracking itself was introduced
> in 2.9.0.

### [Unreleased] - 2026-10-23

#### Added

- **Update script.** `update.sh` backs up the configuration (`.env` as
  `env`, `secrets/`, and the `dropjak.service.d` systemd drop-in) and the
  runtime state (the Docker `dropjak-state` volume and/or
  `/var/lib/hatarvedelem`) into `/root/dropjak-backups` (mode 0700,
  archives 0600; `HV_BACKUPS` overrides), then runs `git pull --ff-only` in
  the checkout. The backup never goes into the repository: a backup directory
  at or below the checkout is refused. `--dry-run`/`-n` previews without root
  and creates nothing, `--yes` skips the `y/N` confirmation. A failed backup
  aborts before git; a dirty or diverged pull fails cleanly with the backup
  intact. After a successful pull it only prints the follow-up: `hv rebuild`
  (or `DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .` and
  `docker compose up -d --force-recreate`) for Docker, and a re-run of
  `install.sh` with the same arguments for native. `install.sh` copies it
  into the installation directory with mode 0755. New `tests/test_update.py`
  (syntax, help, git dry-run, repository guard, root requirement, non-git
  dry-run); the measured suite is **1151 tests OK**.
- **Uninstall script.** `uninstall.sh` removes a Dropjak installation for
  both deployment styles: it tears down the Compose stack, containers, local
  image tags and volumes (unless `--keep-data`), stops and disables the
  systemd units, deletes the `dropjak0` WireGuard interface and the
  `inet hatarvedelem`/`inet hatarvedelem_boot` nftables tables, removes the
  installed files, the `hatarvedelem` user/group and finally the installation
  directory and the script itself. `--dry-run`/`-n` previews without root,
  `--keep-data` preserves `dropjak-state` and `/var/lib/hatarvedelem`, and
  `/root/hatarvedelem-backups` is always kept. The install directory is
  refused unless it contains a Dropjak marker file. `install.sh` copies the
  script to `/opt/hatarvedelem/uninstall.sh` with mode 0755. New
  `tests/test_uninstall.py` (syntax, help, both marker layouts in dry-run,
  root requirement, dangerous-directory guard); the measured suite is
  **1145 tests OK**.
- **No default rules on a fresh installation.** The shipped
  `services.json` has an empty `scenarios` list, so a new installation's
  rules file starts empty instead of being seeded with the four old
  scenarios (Browsing, Work, Administrator, Full). The admin creates the
  rules on **Admin → Rules**. Existing installations are untouched: their
  `rules.json` already holds the earlier rules, and the rule store still
  seeds scenarios if a custom `services.json` defines them. The
  rules-editor catalog and the service-based port conversion are unchanged.
  `tests/e2e_vm.py` now creates the `browse`/`full` rules it logs in with
  and removes them in cleanup.
- **Access mode in `configure.sh`; first-start proxy seed.** The optional
  “Portal DNS name” question is replaced by a choice between
  `http://<host-ip>:PORT` (plain HTTP, default, no proxy variables) and
  `https://<subdomain>` (root domain plus a Dropjak subdomain strictly under
  it, HTTPS through Caddy). HTTPS mode writes `HV_PROXY=1`,
  `COMPOSE_PROFILES=proxy`, a generated or preserved `HV_PROXY_KEY`,
  `HV_PROXY_DOMAINS`, `HV_PORTAL_DOMAIN`, `HV_PORTAL_URL`,
  `HV_PORTAL_HOSTS` and `HV_WAN_HTTPS_ONLY=1`, validates the DNS names,
  re-prompts on a subdomain outside the root, and prints the
  A/wildcard-A/DNS-only/no-AAAA requirement. `gateway.py` reads
  `HV_PROXY_DOMAINS`/`HV_PORTAL_DOMAIN` as a first-start seed and calls the
  new `SettingsStore.seed_proxy()` only while `firewall-settings.json` does
  not exist; afterwards Admin → Settings → Proxy stays authoritative, and an
  invalid seed is logged as a warning instead of stopping startup.
  `docker-compose.yml`, `.env.example`, the installation section and the
  settings table document the variables. New `test_configure` HTTPS-mode and
  seeding tests (invalid subdomain, key preservation, existing-file
  protection, invalid seed warning).
- **Single-NIC mode (`HV_SINGLE_NIC=1`, default `0`).** One interface does
  both jobs: `HV_WAN_IF` is also the client-facing interface, and the portal
  is reached by source-IP matching (`HV_PORTAL_NET`); `HV_LAN_IF`/
  `HV_LAN_NET` are not required and are ignored (logged when set). Every
  LAN-only line of `deploy/dropjak.nft` is marked at column 0 with
  `__LANONLY__`; `docker/entrypoint.sh` and `install.sh` substitute the
  marker with nothing in two-NIC mode and with `# ` in single-NIC mode, so
  the rendered ruleset contains no active `iifname "<LAN>"`, LAN spoof or
  MAC-binding drop, DHCP 67, LAN DNS, captive `redirect`, `masquerade`,
  WAN→LAN guard, container-pivot or LAN input-block rule. Grants, fail2ban,
  `no_forward_v4`, the container guards, IPv6 drop, breakglass, pre-auth,
  tunnels, port proxies, the proxy 80/443 accepts, the source-based portal
  accept and host input accepts stay active.
  `gateway.py` sets `LAN_NETWORK = None` and `MAC_BINDING`/`mac_binding =
  False` in this mode even with stale LAN values, so grants are IP-based on
  the public interface (documented trade-off) and no ARP lookup runs. Input
  pre-auth with `lan` scope uses the WAN interface; forward pre-auth keeps
  the DNAT-only condition on the WAN; port-proxy `lan`/`both` sides map to
  the WAN interface; the admin `block` chain stays forward-only because the
  LAN input jump is omitted. `server.py` warns at startup and recommends
  `HV_PROXY=1` or `HV_WAN_HTTPS_ONLY=1` for a public portal.
  `configure.sh` selects the mode interactively, `install.sh` accepts
  `--single-nic`, and `docker/setup-host.sh` omits the LAN IPv6 sysctl.
  `docker-compose.yml`, `.env.example`, the configuration/installation
  sections and section 9 document the new variable. New
  `tests/test_single_nic.py` (rendering both modes, MAC binding, grants,
  pre-auth, port proxy), updated `test_configure.py`, `test_installer.py`,
  `test_block_precedence.py` and `test_port_ranges.py`; the measured suite is
  **1133 tests OK**.
- **Domain-mode service in a service rule.** The `target_host` +
  `domain` mode tunnel service (without a WAN port) can now also be
  selected as `service_refs`, while remaining available unchanged as a
  domain rule. Saving the rule without a port also succeeds if at least
  one referenced service is domain-mode; the `Rule` authorizes the domain at
  the proxy gate based on the resolved `service_domains`, and the session
  based on `session_domains` (explicit `domains` + service domains,
  deduplicated). On the nft side there is no new port in this case; the
  grant is empty.
- **Mixed rule.** A rule referencing one port and one domain service still
  provides the ports as a forward grant, and additionally opens the domain.
- **Fail-closed and revocation.** A disabled/removed service provides no
  domain, and `_rule_available()` also checks the match of
  `session_domains`. The mapping signature also includes the domain ordering
  (`("domain", …)`), so renaming the domain invalidates the previous decision
  and revokes the affected sessions; `reflect_services()` also updates the
  `service_domains`/`session_domains` values (in collections too).
  The service editor's change detection (`_tunnel_effective_ports`) treats
  the domain as part of the effective mapping, so even when the internal
  listening port is left unchanged, the referencing rules are refreshed and
  the sessions are revoked. The selection (`RuleSelection`) preserves the
  `service_refs`/`service_domains` fields, so the authorized user sees the
  selected service's label in the `/api/status` response.
- **API and UI.** The `services` payload has the form `{ref, label, tcp, udp, domain}`;
  for a domain-mode service, `ports_label` is “Service: <label>
  (<domain>)”. The rule form's service picker offers domain-mode
  services marked ` · Domain`, the help states that the
  domain opens through the portal proxy, and the rule row shows the domain
  next to the service name. New hu/en/de `domain` label.
- **Tests.** Five new `test_gateway` (save, mixed rule, disabled
  reference, signature rename, session authorization), two new
  `test_tunnels` API/session/revocation tests (including a rename that
  follows the real UI payload with an unchanged internal listen port) and one
  new `test_tunnel_ui` static test; the measured suite is **981 tests OK**.
- **`configure.sh` — interactive configuration.** Asks for the LAN and WAN
  interfaces (listing them with their addresses), the LAN network, the portal
  source network, the management network, the portal port, an optional portal
  DNS name and the first admin account, then writes `.env` with mode 0600.
  Re-running it offers the current values as defaults and backs up the old
  file. An empty admin password is generated. New `tests/test_configure.py`.

#### Changed

- **The portal is public by default.** When `HV_PORTAL_NET` is unset or
  empty, the portal is reachable from the WAN (`0.0.0.0/0`) instead of
  falling back to `HV_MGMT_NET`. `configure.sh` proposes the same default and
  writes it to `.env`; the installer and `.env.example` follow it too. The login is guarded by the admin account,
  the proof-of-work captcha and fail2ban; the startup warning about serving
  a public portal over plain HTTP remains. `HV_MGMT_NET` now only supplies
  management defaults (for example the fail2ban exemptions) and does not
  narrow the portal or allow SSH. Set `HV_PORTAL_NET` to a CIDR to keep the
  portal off the WAN.

#### Fixed

- **Image build on a gateway host.** The fail-closed forward chain also
  drops the build container's traffic, so apt-get had no DNS
  (`Temporary failure resolving 'deb.debian.org'`). Compose cannot request
  host networking for the build either — buildx bake refuses it with
  `additional privileges requested` — so the image is built explicitly on the
  host network (`DOCKER_BUILDKIT=0 docker build --network host -t dropjak:2 .`)
  and then started with `docker compose up -d`. The README, the installation
  sections, the setup script's closing message, `.env.example` and
  `hv rebuild` follow this order.

#### Security

Fixes from the 2026-10-23 security review (finding IDs DJ-00 to DJ-36).
Items marked as design steps in that review (DJ-24, mandatory admin TOTP,
TOTP enrollment codes, encrypted export) are not part of this change
(agent-side key generation is, see the last entries); the owner's decisions on the other follow-ups
are the last entries of this list.

- **fail2ban (DJ-01, DJ-22).** Ban rules match only `ct direction original`,
  so a ban no longer drops replies to LAN clients. Drop-signal bans skip an
  allowlist: `HV_MGMT_NET`, `HV_FAIL2BAN_DROP_EXEMPT`, the resolvers and the
  default gateway (built in), plus the editable `drop_exempt` list. Manual
  bans are never evicted; a registry full of manual bans refuses new bans.
- **Firewall template (DJ-02, DJ-03, DJ-16, DJ-17, DJ-18, DJ-19, DJ-33,
  DJ-34).** No forwarding to `169.254.0.0/16`; new flows into Docker bridges
  and WAN→LAN need DNAT; DOCKER-USER no longer accepts marked packets toward
  bridges; established UDP 53 flows end on revocation; LAN-network sources
  only on the LAN interface; host accepts use the rendered portal port; the
  boot table's input chain is `policy drop`; input `jump block` and the
  `host_service_*` guards spare reply traffic.
- **Table resync (DJ-04).** A reloaded or flushed `inet hatarvedelem` table
  is detected within 5 s and its bans, host guards and custom chains are
  restored (`firewall_resync` audit); grants are refused until then.
- **Auth (DJ-06, DJ-11, DJ-12, DJ-14, DJ-26, DJ-27, DJ-29).** Per-account
  lock across WAN source IPs (`HV_ACCOUNT_LOCK_*`); export (now POST),
  import and reset need the admin password and TOTP code again; TOTP
  enrollment is an audit alert; `/api/*` answers 421 under an unknown
  `Host` (`HV_PORTAL_HOSTS`); the audit log keeps the session id, not a
  token prefix; the provisioning marker has a random salt; case-variant
  user names are refused and PBKDF2 hashes are rehashed to the current
  count.
- **Proxy trust (DJ-10, DJ-28).** `HV_PROXY_KEY` shared by the portal and
  Caddy (mandatory with `HV_PROXY=1`, see below). Caddy sends HSTS; the CSP
  lists Cloudflare only with Turnstile.
- **Portal server (DJ-00, DJ-13, DJ-15).** Startup warnings for a public
  plain-HTTP portal; connection caps (`HV_MAX_CONNECTIONS`,
  `HV_MAX_CONNECTIONS_PER_IP`); tunnel peers reach only
  `GET /api/tunnel/config`.
- **Drop log (DJ-07, DJ-31).** `ENOBUFS` no longer stops the listener, other
  errors restart it with back-off, no fsync per packet; reads stop at the
  limit instead of parsing every rotated file.
- **Settings (DJ-09, DJ-36).** Input pre-auth cannot open 22, 53, 67, 2019
  or the portal port; destinations with host bits are rejected when saved.
- **Containers and installers (DJ-08, DJ-20, DJ-21, DJ-23, DJ-30).** The
  agent installer prints its SHA-256 (the portal sends `X-Dropjak-SHA256`),
  installs as root into a private 0700 directory and refuses unsafe
  directories; the portal's capability bounding set is cut to `NET_ADMIN` and
  `NET_BIND_SERVICE` (`SETPCAP` added to compose for this); the admin
  password can come from `./secrets/dropjak_admin_password`; the agent
  refuses every route next hop as a target; the Caddy admin socket is 0660.
- **Other.** `docker/entrypoint.sh` exports `HV_PORTAL_NET`, defaulting it to
  `0.0.0.0/0` (public portal) when it is unset or empty.
- **Sessions after a table resync (DJ-04, decision a).** After a successful
  resync every authorized session ends with reason `firewall_reset`
  (fail-closed): one `session_ended` audit per session, `sessions_revoked`
  on `firewall_resync`, conntrack flushed, and a hu/en/de explanation on
  the client, which logs in again.
- **Input block only for LAN traffic (DJ-33).** The input chain's block
  jump is `iifname "<LAN_IF>" ct direction original jump block`, so a
  destination-less block entry (for example TCP 443) no longer stops
  inbound WAN traffic to Caddy. The forward jump is unchanged; no post-DNAT
  matching.
- **Provisioning marker out of the export (DJ-27).** Exports no longer carry
  `provisioned_from`. On import a record without a marker keeps this
  installation's marker for the same user; for `HV_ADMIN_USER` without one a
  fresh marker of the current `.env` password (`HV_ADMIN_PASSWORD` or its
  file) is stored, so the next start does not reset a UI-changed password.
  Old bundles with a marker still import; the private pre-import backup
  keeps the markers so a rollback restores the exact state.
- **Mandatory proxy key (DJ-10).** `docker/entrypoint.sh` refuses to start
  (exit 1) when `HV_PROXY=1` and `HV_PROXY_KEY` is shorter than 32
  characters; the message says to run `openssl rand -hex 32` and put the
  value in `.env`. The check runs before the firewall is touched and does
  not apply to CLI commands. The native install has no proxy, so it needs no
  key. fail2ban's `_AUTO_EXEMPT` (`127.0.0.1`) is removed; `127.0.0.1`
  itself stays unbannable through `normalize_ip`. The startup warning says
  the key is required.
- **WAN HTTPS-only switch (DJ-00).** New `HV_WAN_HTTPS_ONLY` (default `0`):
  with `1`, `/api/login*`, `/api/password` and `/api/admin/*` answer
  `403 {"code": "https_required"}` to non-LAN sources that did not come
  through Caddy; LAN and loopback-direct callers are unaffected. Refusals
  are audited as `https_required` (at most once per IP per minute, hu/en/de
  labels). Responses through Caddy get a `Secure` session cookie even with
  `HV_COOKIE_SECURE=0`, so plain-HTTP LAN logins keep working. The
  plain-HTTP startup warning is silenced by the switch; a new warning flags
  the switch without `HV_PROXY=1`.
- **Container bridges (DJ-03).** The entrypoint reads every bridge
  interface (`ip -o link show type bridge`, without the LAN and WAN
  interfaces) into the new `docker_bridges` nft set; new flows into those
  need DNAT like `docker*`/`br-*`, and the `DOCKER-USER` accept excludes
  them too. The watchdog refreshes both. A missing `DOCKER-USER` chain or
  Docker's nftables backend is no longer fatal: the container keeps running
  and logs a loud `ERROR` at start and at most once a minute.
- **Input pre-auth scope (DJ-09).** Input pre-auth entries have a `scope`,
  `lan` (default; stored entries without it load as `lan`) or `any`. `lan`
  renders `iifname "<LAN_IF>"` only (also for the established accept);
  `any` keeps the LAN + WAN behaviour. Validated in `settings_store`, part of
  export/import, and a **Scope** select (hu/en/de) in the pre-auth form. The
  reserved-port rule is unchanged.
- **Hand-edited settings (DJ-36).** Saving stays strict, but loading a
  stored file normalizes a destination with host bits to its network with a
  logged warning instead of invalidating the file. `Firewall._custom_dst`
  stays strict.
- **IPv6 always dropped (DJ-35).** The input chain drops IPv6 before the
  `breakglass` jump (only loopback precedes it), the raw prerouting
  `loopback_guard` drops every non-loopback IPv6 packet, and the boot
  table's input and prerouting chains drop IPv6 too. `docker/setup-host.sh`
  (reading `HV_LAN_IF` from `.env`) and `install.sh` write
  `net.ipv6.conf.<LAN_IF>.disable_ipv6 = 1` into
  `/etc/sysctl.d/90-dropjak.conf` in two-NIC mode (omitted in single-NIC
  mode, which has no separate LAN interface); `setup-host.sh` no longer
  inserts an IPv6 SSH exception into the boot table. Requirement: no other
  IPv6 router on the client LAN.
- **Private proxy entries bound to the session (DJ-05).** The source IP is
  no longer enough: `/api/proxy/auth` also requires a `__Host-dropjak_bind`
  cookie (HMAC over session id, host and expiry) naming the IP's live
  session for that entry. It is set by a two-hop flow: the portal's
  `GET /api/proxy/bind` (session cookie required) issues a single-use 60 s
  ticket, and `/__dropjak/bind` on the entry trades it for the cookie.
  Navigations without the cookie are redirected into the flow, other
  requests get 401 (not counted by fail2ban). Private domain-mode tunnel
  services go through the same check. Caddy strips both
  `__Host-dropjak_(pass|bind)` cookies before the upstream. New audit events
  `proxy_bind_completed`, `proxy_bind_denied` and `proxy_bind_failed`
  (hu/en/de labels).
- **No inline-script allowance in the CSP (DJ-28).** `script-src` no longer
  has `'unsafe-inline'`; the inline scripts of `index.html` and of the
  challenge page are allowed by SHA-256 hashes computed from the served
  page.
- **`__Host-hv_session` over HTTPS (DJ-28).** When the session cookie is
  `Secure` (through Caddy, or `HV_COOKIE_SECURE=1`) it is issued as
  `__Host-hv_session`; plain-HTTP LAN logins keep `hv_session`. Both names
  are read, and logout clears both.
- **TOTP ticket race (DJ-29).** Code checks reserve an attempt before
  verifying (`reserve`/`fail_reserved`/`release`), so parallel wrong codes
  cannot exceed the ticket's cap. The approval list warns about pending
  names that resemble an admin name.
- **Installer digest in the UI (DJ-08).** The agent card shows the
  downloaded installer's `X-Dropjak-SHA256` value with a hint to compare it
  with `sha256sum`.
- **Agent-side WireGuard keys (DJ-08 step 7, DJ-25 agent-key half).** "New
  agent" stores `public_key: null`, the SHA-256 of a one-time enrollment
  token and a 30-minute expiry; the token is shown once. The installer
  bundle (`agent.json` version 2) carries no private key, PSK or sync token,
  only the enrollment token; downloading it needs the token
  (`X-Dropjak-Enroll-Token`). The agent generates its key pair and PSK,
  keeps them 0600 in its state volume and enrolls over the portal's public
  address (HTTPS when available) at the new `POST /api/tunnel/enroll`:
  constant-time hash check, expiry, single use, 10 attempts per 5 minutes
  per IP, `HV_WAN_HTTPS_ONLY`, audited as `tunnel_agent_enrolled` /
  `tunnel_enroll_failed` (hu/en/de labels). The portal stores the public key
  and PSK and returns a sync token once, keeping only `sync_token_hash`;
  `_tunnel_config_sync` compares `sha256(bearer)` with `hmac.compare_digest`.
  No peer exists until enrollment ("waiting for enrollment" in the UI).
- **Migration of existing agents.** Agents with stored `private_key`/`token`
  keep working unchanged. The new **Re-enroll** button deletes the stored
  private key, PSK and plaintext token, issues a new enrollment token and
  downloads a new installer; run it on the agent host (the agent replaces
  its identity automatically). Settings validation and export/import accept
  both shapes; an enrolled agent's export holds only its public key, PSK and
  token hashes.

### [3.24.0] - 2026-10-22

#### Added

- **Multi-port tunnel services.** The stored form of a service is
  `{id, label, target_host, enabled, public, domain, mappings:[{proto, listen, target}]}`.
  `listen` and `target` accept a list and a range (`80,443`,
  `8000-8100`); the elements on the two sides are paired by index, so their
  counts must match. A service, agent and mapping can have at most 256 ports.
  Legacy single-port services migrate automatically to the new schema on
  load; when `public` and `domain` are missing they become `false` and empty.
- **Public (portal-free) port services.** A service's
  `public: true` flag, for a port-mode service, generates pre-auth accepts
  scoped to the WAN interface for the TCP/UDP protocol of every listening
  port: a `ct status dnat` and a `ct state established`
  rule, with the `ct original proto-dst` port and the forward mark set.
  The LAN branch and the `related` rule are not created; `jump block` stays
  before pre-auth. The rules disappear automatically when the service is
  disabled, deleted, becomes private or becomes a domain service, and do not
  affect the user's pre-auth entries. Without a known WAN interface, saving
  returns an error.
- **Domain tunnel services.** If the service's `domain` field is not
  empty, the service is domain-mode: it requires exactly one `tcp` mapping and
  a target host, reserves no WAN port, and gets no port-proxy entry
  or DNAT. The domain is a lowercase FQDN (at most 253 characters, labels of
  1–63 characters, `[a-z0-9-]`, at least one dot), a strict subdomain of the
  configured proxy root domain (the longest matching root), cannot be
  equal to the root domain, the portal domain or a port-proxy host,
  and is unique among tunnel services. The internal listening port is
  allocated by the server from the 41000–60999 range (the lowest free one),
  skipping the explicit listening ports, the reserved ports, the
  WireGuard port and the portal port; if there is no free port, saving
  returns an error. `_proxy_target` resolves an enabled service of an enabled
  agent to the agent's tunnel address, and Caddy's `/api/proxy/ask`
  and `/api/proxy/auth` endpoints apply the domain rule:
  if `public`, they let the request through without a session; if private,
  the grant of the rule for the domain is required. The agent configuration
  wire format is unchanged (the `domain`/`public` fields are not included).
  If a domain rule references the service, deleting the service/agent and
  changing the domain are rejected with a Hungarian error message; disabling
  is allowed even with a reference (fail-closed, with session revocation).
- **Service rule.** A new rule type with a `service_refs: ["<agent_id>/<service_id>"]`
  field; it provides the referenced services' listening ports as forward
  grants, with both protocols for mappings merged into `both`. 1–64
  references; the referenced service must exist and be enabled; the rule
  cannot be combined with the `tcp`, `udp`, `icmp`, `full`,
  `members` or `domains` fields. It can be a collection member; the union
  applies there too.
- **Direct rule assignment via the API.** The rule create/update request
  accepts optional `users` and `groups` fields; this is the rule's exact direct
  assignment set. The server sets the `users.rules` and `groups.rules` lists
  separately with atomic file writes, audits the added and removed
  elements; group membership remains unchanged.
- **UI.** The service editor inside the agent card adds dynamic
  mapping rows (protocol, external port, internal port, add/delete) and
  checks the count on the two sides on the client side. On the rule form,
  every rule type has a `Users` and a `Groups` selector, as well as a
  `Service` checkbox and a reference selector; the rule cards and
  the session view show service labels (`Service: …`). New
  hu/en/de texts and error messages.
- **Service reachability test.** A **Test** button in every service
  row of the agent card (`tunnel_service_test` admin action) checks the whole
  path from the portal host through WireGuard to the agent's
  DNAT: it opens a TCP connection to the agent address's port used by
  Caddy/DNAT, with a 2-second timeout. For `udp`/`both`, a zero-byte UDP
  probe is also sent (silence = success, ICMP unreachable =
  failure). At most four mappings run in parallel, for at most six
  seconds; the response per mapping is `{proto, listen, target, ok,
  detail}` plus a Hungarian summary. The action is read-only (no settings
  write, nft change or restart), and writes a `tunnel_service_test`
  audit entry with identifiers, protocols, ports and results, without a
  token or key.
- **Redesigned tunnel panel.** Within the **Proxy and tunnels** tab, the
  agent/service list gets its own block: a collapsible “New agent”
  form, an agent card with a header (name, monospace address, online/offline
  badge, toggle, right-aligned actions), a single meta row and columnar
  service rows (Name, Target, Access, Status, Actions). Only one
  editor or add form is open at a time; the Test result appears below the row
  in a green/red badge, even on an API error. On a narrow
  screen the rows turn into label/value pairs, and deletion remains
  two-step.

#### Changed

- **Playit.gg-like home agent.** The installer is one-command: it installs
  into the current directory, and on a TTY interactively selects from a
  numbered list the **one** network to which the agent connects
  (`playitgg-net` first/default, if present). In non-interactive mode,
  `DROPJAK_NETWORK` overrides, otherwise the default decides (not a TTY
  or `DROPJAK_NO_PROMPT=1`). If there is no bridge network, it stops with an
  error; it does not join every bridge network, and does not fall back to
  `bridge`. The selected network must have the bridge driver (`host`/`none`
  are rejected), and the compose contains exactly one
  `external: true` network without a host-gateway entry.
  With this, the agent reaches only containers on this network. The
  previous `dropjak-home` (`internal: true`) + `egress` pair and the
  multi-network `dropjak-agent-networks.timer`/`reconcile-networks.sh`
  are gone; on upgrade the installer removes them. `agent.py`
  still assigns the target IP to the attached subnet with the longest
  prefix, renders the forward, DNAT and postrouting rules per interface,
  and fail-closed rejects a target outside the attached subnet.
  `check-containment.sh` checks exactly one bridge network and the
  container's security settings. The `compose.example.yml` and
  `compose.agent.yml` samples show the single shared network model;
  the host (bridge gateway) is intentionally not a tunnel target.
- **English-language installer and delete action.** Every output and comment
  in `selfinstall.sh` and `check-containment.sh` is in English. The
  `delete` / `--delete` / `-d` first argument removes the agent's container
  without network selection and installation (compose down, or
  `docker rm -f` as a fallback; exits with 0 if there is nothing to delete).
  On a TTY, a `1) Install/update (default)` / `2) Delete container` menu
  offers the action at startup, and a successful installation prints the exact
  delete command.
- **Unique agent container names for multiple agents.** The installer derives
  the `container_name` from the packaged `agent.json` label and identifier
  (`dropjak-tunnel-agent-<label-slug>-<id>`, with accent
  transliteration, at most 63 characters; for an empty label,
  `dropjak-tunnel-agent-<id>`), writes a `container-name` (0644) file next to
  the compose, and uses it in its messages, in the `delete` action (keeping
  the old fixed name as a fallback) and in the `DROPJAK_CONTAINER` value passed
  to `check-containment.sh`. The containment check uses the single container
  discovered with the `dropjak-tunnel-agent` prefix; with several matches it
  lists the names and asks for `DROPJAK_CONTAINER=<name>` to be set. Multiple
  agents on one host work with separate installation directories.
- **No separate tunnel port.** In port mode, the internal tunnel port always
  matches the external `listen` port; the old `tunnel_port` field and
  the 41000–41999 allocator are gone from the service schema (in the agent's
  wire format, `tunnel_port` still denotes the listening port). Only the
  domain service gets an internal port automatically from the 41000–60999
  range (the lowest free one, skipping the explicit listening ports, the
  reserved ports, the WireGuard port and the portal port). The agent's
  wire format is unchanged (one entry per listening port,
  `id="p<port>"`, `target` = `host:port`); the server expands the
  mappings.
- **Global listen namespace.** The `(proto, listen)` pair is unique across
  services and port proxies together; the reserved listening ports (22, 53,
  67, 80, 443, 2019, the portal's port 8100 and the active WireGuard UDP port)
  are checked within ranges too, and on the target side 22 and 2019 are
  prohibited. TCP and UDP mappings with the same `listen`/`target` pair merge
  into `both`; the same `listen` with a different `target` is rejected.
- **Configuration bundle.** The `settings` section also includes the multi-port
  services and their mappings; older bundles import unchanged.
- **Tests.** The full suite is 981 tests, all OK. New groups: multi-port
  schema, expansion of lists/ranges and `both` merging,
  service rules, direct assignment, lifecycle constraints, and
  the single-network agent installer (interactive numbered network
  selection, default, `DROPJAK_NETWORK` / `DROPJAK_NO_PROMPT`, `delete`
  action and fallback `docker rm -f`, cleanup of the old timer) and the
  containment check.

#### Security

- Changing the mapping or the enabled state recalculates the grants of the
  referencing rules and revokes the affected sessions. The referenced service
  or agent cannot be deleted while a rule references it; the operation is
  rejected with the list of referencing rules. Disabling is allowed even with
  a reference (fail-closed, with session revocation).
- Authorization re-resolves the `service_refs` list at decision time,
  and fail-closed rejects differing ports, a missing or a disabled reference.
  The old bare `rules` list fallback gives no automatic grant for a service
  rule.

#### Fixed

- The obsolete separate tunnel-port field is gone from the service editor,
  along with the remnants of the old single-port allocator.
- **Tunnel deletion with in-page confirmation.** Deleting an agent or a service
  no longer uses the native `confirm()`, which the browser can disable (in
  which case deletion was silently skipped). After the first click, the
  card/row changes in place: it shows the warning, as well as the
  red “Delete” and “Cancel” buttons; the deletion payload is unchanged.

### [3.23.3] - 2026-10-22

#### Fixed

- **Agent DNS on rootless Podman**: the agent's own nftables output chain
  allowed DNS only to Docker's embedded resolver (`127.0.0.11`), while
  rootless Podman uses the bridge gateway from `/etc/resolv.conf`. Target
  names failed to resolve (`[Errno -3] Try again`), so no rules were applied.
  The agent now reads the IPv4 nameservers from `resolv.conf` and allows DNS
  to each of them.
- **Agent target interface on an existing Docker network**: when the agent
  joins a pre-existing (non-internal) network, both that network and the
  egress network can carry a default route. The agent mistook the target
  interface for the egress one and rejected it (`routes via eth0, not the
  internal network`). The default-route check was removed; the target must
  still be a non-gateway container address on the target interface's subnet.

#### Changed

- **Proxies and tunnels on one admin page**: the separate Proxy and Tunnels
  tabs are merged into “Proxy and tunnels”. Direct nftables port proxies need
  no agent; tunnel agents and their services are shown below them. The
  installer points to the merged page.

### [3.23.2] - 2026-10-22

#### Changed

- **Agent installer defaults to the current directory**: the single-file
  installer now extracts into `$PWD` (the directory it was run from) instead
  of `$HOME/dropjak-agent` or `/opt/dropjak-agent`. The directory is still
  asked interactively, and the sudo re-exec passes the original directory.

### [3.23.1] - 2026-10-22

#### Fixed

- **Home agent on SELinux / rootless Podman**: the agent config mount uses
  the `:Z` relabel option (otherwise the container cannot read `agent.json`
  and exits with code 2), the compose sets
  `net.ipv4.ip_forward=1` via `sysctls`, and the agent treats an already
  enabled sysctl as success when `/proc/sys` is read-only.
- **Tunnel manager address error**: the WireGuard server address is now set
  with `ip addr replace` instead of `addr add`. A restarted portal container
  that keeps its network namespace already has `10.77.0.1/24` on `dropjak0`,
  and `add` failed with `ipv4: Address already assigned`, leaving the manager
  in an error state and skipping peer sync.

### [3.23.0] - 2026-10-22

#### Added

- **One-file tunnel-agent installer**: the Tunnels tab now downloads a single
  self-extracting `dropjak-agent-<id>.sh`. On the home machine
  `sudo sh dropjak-agent-<id>.sh` asks for the install directory, checks
  Docker and Compose, offers an existing Docker network or a new isolated
  `dropjak-home`, unpacks the agent compose file, its `agent.json`
  (WireGuard keys and token, mode 0600), the Dockerfile and the agent
  sources, then builds and starts the agent. The previous JSON config
  endpoint is kept for existing setups.

### [3.22.0] - 2026-10-22

#### Added

- **Root-domain service entries**: the subdomain field of a proxy entry may be
  left empty, making the root domain itself the host. Such an entry works like
  any other (Input/Forward, port, visibility, challenge) and domain rules can
  reference it. It can only be saved while a dedicated portal address is
  active, and that address cannot be cleared while one exists.

#### Changed

- With a dedicated Dropjak address, root domains are no longer claimed by the
  portal: without a root entry they do not redirect to it and get no
  certificate (port 80 answers 404). Unknown, certificate-uncovered names
  still redirect to the portal on port 80.

### [3.21.1] - 2026-10-22

#### Fixed

- **Dropjak web address input**: a pasted full URL (`https://…/`), a trailing
  dot or a port is normalized to the bare hostname before validation. A
  rejected address now stays in the field instead of being cleared, so the
  error message can be fixed without retyping it.

### [3.21.0] - 2026-10-22

#### Added

- **Dedicated Dropjak web address** (`portal_domain`): Settings → Domain
  settings can move the portal UI to its own Caddy address under a configured
  root domain (e.g. `dropjak.z1.example.com`). When set, the root domains
  redirect there and the entry appears on the Domains tab among the proxy
  entries. Its address, type, port and visibility are fixed (they come from
  the running portal) and it has no delete button; only its challenge can be
  edited there. Turning it off in Settings removes the entry. The setting is
  validated: it must be an FQDN under a configured root and must not collide
  with a proxy entry; removing the parent root while the address is active is
  rejected.
- **`ok.png`** is served by the portal (`/ok.png`) and replaces the “Network
  enabled” status pill on the open-session view; the countdown, stats and
  actions are unchanged.

#### Security

- The dedicated portal host gets the same loopback-endpoint protection as a
  root domain: `/api/proxy/*` is not reachable through Caddy on it, even
  though the upstream is the portal itself.
- The portal address is public like the root portal; a challenge can be
  configured for it and is enforced through the existing `forward_auth` path.

### [3.20.0] - 2026-10-22

#### Added

- **Tunnels tab (WireGuard).** A separate admin tab manages cloud-to-home
  tunnels like playit.gg: agents, their services and per-agent config
  downloads. The cloud creates `dropjak0` (`10.77.0.1/24`), listens on a
  configurable UDP port (default 51820) and keeps one `/32` peer per enabled
  agent, with a per-agent preshared key and token.
- **Home agent** (`deploy/tunnel-agent/`): a stdlib-only Python container
  that joins an `internal: true` Docker network as a second interface and
  applies a default-drop nft ruleset in its own network namespace. Only the
  mapped tunnel ports can reach the containers; internet, LAN, the Docker
  host and other containers are not reachable. `check-containment.sh`
  verifies this on the home host.
- **Automatic sync:** the agent polls `GET /api/tunnel/config` over the
  tunnel with a Bearer token. The endpoint requires the exact raw peer
  address of an enabled agent, compares the token in constant time and is
  rate-limited per agent. The response contains only that agent's services.
- **Tunnel services** are rendered as synthetic forward port-proxy entries:
  WAN-scoped DNAT to the agent's WireGuard address plus SNAT to
  `10.77.0.1` so return traffic stays on the tunnel.
- **Config bundle v2** includes the `tunnels` section (agent keys, PSKs and
  tokens); v1 bundles still import with defaults. Factory reset removes the
  tunnels and their peers.

#### Security

- **Tunnel traffic remains portal-gated.** No pre-auth accept is generated
  for tunnel services; the existing forward-chain
  `ct original ip saddr . ct original proto-dst @allowed_tcp/udp` rule
  authorizes a client only after login and rule selection. An explicit
  pre-auth rule is the only way to make a tunnel public. The admin UI states
  this next to the service form.
- The WireGuard UDP port is accepted only on the WAN interface, only while
  at least one agent is enabled; without agents the `tunnel_input` chain is
  empty and the port is closed. Disabled or deleted agents lose their peer.
- The agent config parser rejects `allowed_ips` outside `10.77.0.0/24`, so
  the home side cannot be turned into a full-tunnel client by a bad config.
- WireGuard private keys and PSKs reach `wg` through 0600 temporary files on
  tmpfs and never appear in the command line.

#### Fixed

- Removed the pre-auth accept that would have made every tunnel service
  reachable without a portal grant. Tunnel services now follow the same
  authorization path as port proxies, including fail2ban accounting.

### [3.19.2] - 2026-10-22

#### Fixed

- **The blocking page's sign-in button is below the image, centered.** Since
  the shield icon was removed, the image and the `inline-flex` button ended up
  on one line, so the button slid to the bottom-right corner of the image. The
  image is now block-level, with automatic margin; the button uses `display:flex`
  + `width:max-content` + `margin:20px auto 0`.

### [3.19.1] - 2026-10-22

#### Fixed

- **The proxy challenge page's captcha appears again.** In 3.18.0 the English
  label got into the embedded script with a Python escape
  (`\'I\'m not a robot\'`), which is invalid JavaScript; the whole script
  did not even run, so the captcha was not built. The label's quotation mark is
  now `"`.
- The shield icon was removed from the challenge and blocking pages; the
  challenge page keeps only the `sus.png` image and the captcha, the blocking
  page the image and the icon-only sign-in button. A node `--check` test now
  catches the skipped JS.

### [3.19.0] - 2026-10-22

#### Added

- **Configuration bundle (config flash).** The Settings tab now exports the
  whole configuration to a versioned JSON bundle, imports it back and offers a
  factory reset. The bundle envelope is
  `{"format": "dropjak-config", "format_version": 1, "app_version",
  "created_at", "sections"}`; `sections` always carries `settings`, `rules`,
  `groups`, `users`, `certs` and `fail2ban`. Missing, unknown or
  unsupported-major sections are rejected instead of being dropped.
- **Export** (`POST /api/admin/config/export`) is admin-only, origin-checked and needs the admin's password (step-up).
  It returns a `no-store` attachment named
  `dropjak-config-<version>-<UTC>.json`. Users carry PBKDF2 hashes, TOTP
  secrets, recovery-code hashes and the provisioning marker; certificates
  carry their private keys. Audit records only `config_exported`, the byte size
  and section counts.
- **Import** (`POST /api/admin/config/import`, 8 MiB cap) validates the entire
  bundle in memory before the first write: schema/version, settings, user
  records, rules, groups, certificate key/PEM pairs with root coverage and
  expiry (expired pairs are accepted only for restore), the exact fail2ban
  config, referential integrity (rule domains ↔ proxy routes, users ↔ rules,
  groups ↔ rules/members, certificates ↔ proxy domains, collection members)
  and at least one enabled, non-pending admin. A non-empty installation
  requires the typed current site name; a blank installation (only the
  `.env`-provisioned admin and seeded rules) does not. The current state is
  backed up first as a `0600` `config-backup-<UTC>.json` in the state
  directory; writes go through the existing stores. A mid-write failure rolls
  back from that backup and reports `config_import_failed`/`rollback_failed`
  without restarting. Success revokes every session and login ticket, applies
  nftables/fail2ban and restarts the process with `SIGTERM` (Compose
  `restart: unless-stopped`).
- **Factory reset** (`POST /api/admin/config/reset`) always requires the typed
  site name. Runtime state is cleared first (sessions, login tickets, all
  fail2ban bans, nftables flush/custom chains); a failure there returns 503
  and deletes nothing. Then users, rules, groups, settings, fail2ban state,
  certificates and old import backups are removed. Audit/drop logs, `.env`,
  service files and assets stay. The `config_reset` event is written after
  deletion and the service restarts, re-creating the `.env` admin.
- **UI.** English and German translations, a secrets warning, an export
  button, an import file picker with typed-site-name confirmation for
  non-empty state, and a danger-styled factory-reset button with typed
  confirmation.

#### Changed

- `CertStore` gained in-memory `validate_import`, `export_all`, `replace_all`
  and `reset`; `UserStore`, `RuleStore`, `GroupStore`, `SettingsStore` and
  `Fail2ban` gained the matching export/validate/replace/reset paths, keeping
  atomic writes, owner preservation and `0600` permissions.
- Imported expired certificate pairs are accepted so an older backup can be
  restored; uploads still reject expired certificates.

#### Security and operations

- Audit records for the new endpoints contain only counts, size, outcome,
  backup filename and revoked-session count — never bundle content, hashes,
  TOTP secrets, recovery codes or private keys.
- Excluded from the bundle: audit/drop logs, sessions, bans/attempts, `.env`,
  `.secret`, PID/socket/lock files and Caddy ACME volumes.
- The `.env` admin remains authoritative after restart: an imported account
  with the same name but a different password is overwritten by
  `provision_admin` (with forced password change on first login).
- A failed import can leave partial runtime state if the rollback itself
  fails; this is reported as `rollback_failed` and the service is not
  restarted.

#### Tests

- HTTP tests cover export headers, sections and exclusions, admin/origin
  enforcement, blank and non-empty import, version/section/referential/admin
  validation with no writes, mid-write rollback, session revocation, restart
  requests, reset semantics (including `.env` preservation and admin
  re-provisioning) and an export → reset → import round trip.
- Static UI and Node tests cover the new section, endpoints, HU/EN/DE strings
  and the non-empty-state helper.

### [3.18.0] - 2026-10-22

#### Changed

- **Textless proxy state pages.** The challenge and unauthorized pages no
  longer render a heading or paragraph. Their state is shown by a 72px
  stroke-based inline SVG icon (a locked shield for the challenge, a slashed
  shield for unauthorized); the `sus.png` and `unauthorized.png` images stay.
  The `<title>` of both pages is "Dropjak". The unauthorized page's
  "Sign in" link is now an icon-only button (door/arrow SVG) that keeps
  the blue rounded look and gets its accessible name from
  `aria-label`/`title`.
- **English captcha on the challenge page.** The PoW widget now says
  "I'm not a robot", "Checking…" and "Verified"; Turnstile runs with
  `language: en`, and the widget's error messages are English too.
- **Product name.** The HTTP `Server` header is now `Dropjak/2` and the
  `server.py user` CLI description names Dropjak. Technical identifiers
  (the nftables table, service/container/volume names, paths and the
  `/root/hatarvedelem` repo path) are unchanged.

#### Tests

- Proxy tests pin the icon-only markup, the English captcha labels, the
  absence of the removed Hungarian page strings and the `Dropjak/2` header /
  CLI description.

### [3.17.0] - 2026-10-22

#### Added

- **Clickable cross-references in the admin UI.** Entity names shown on
  another entity's page are now links that switch to the page where the
  entity is edited and open its editor. Groups → rule and member names;
  Rules → collection members and domain hosts; Users → direct, effective
  and group memberships; Sessions → selected rules and user names. Domain
  hosts open the Domains tab and scroll to/highlight the matching route
  row, since routes have no separate editor. Rule and group columns show
  the human label with the identifier as fallback. Links are focusable,
  keyboard-activatable and carry a localized accessible name. The
  `adminSetTab()` tab switch now returns the state-loading promise so the
  editor opens only after a cold-cache state load has resolved.

#### Changed

- **MOTD modal title.** The notice dialog heading is now the neutral
  "MOTD:" in all three languages instead of the longer "Message of the
  day" wording; the HU/EN/DE dictionary entries were updated together.

### [3.16.1] - 2026-10-22

#### Added

- **Direction on pre-auth entries.** A pre-auth entry now carries
  `direction`: `forward` (default) or `input`. Forward entries keep rendering
  into the `preauth` chain exactly as before; input entries render into the new
  `preauth_input` chain, which the base `input` chain jumps to right after
  `jump block` and before the portal/SSH rules. Input entries accept
  host-destined traffic directly (no forward mark, no `ct status dnat`, no
  `preauth_nat`), match the same proto/destination/port tuple
  (`meta l4proto`, optional `ct original ip daddr`, `ct original
  proto-dst @<port set>`), include a `ct state established` rule for
  continuity, and are scoped to the known LAN and WAN interfaces. If neither
  interface is known the render fails with a Hungarian error. Entries without
  the field load as forward, so existing `firewall-settings.json` files load
  and render unchanged.
- **Security warning.** An input pre-auth rule opens the given host ports
  **before sign-in**, bypassing the portal gate. The `block` chain and
  fail2ban still take precedence, and input pre-auth creates no portal
  session or grant. The UI and DOKUMENTACIO.md state this explicitly.
- **Chain bookkeeping.** `preauth_input` is part of every custom-chain
  enumeration: `clear_custom`, `replace_custom`, the fail-closed
  `keep_block=True` path, the Raw rules view and the nft template (declaration
  plus the `chain input` jump), so a reload or flush never leaves a stale
  chain.

#### Changed

- **Rule form direction control.** The access-rule field is now labelled
  `Irány` / `Direction` / `Richtung` instead of `Típus` / `Type` / `Typ`, and
  the `Domain (proxy)` option moved out of the direction select into a
  separate checkbox. The domain rule submits exactly as before; every
  non-input direction still submits as forward. The port-proxy and Caddy
  `Típus` labels are unchanged.

#### Tests

- Settings: pre-auth direction default, round-trip, invalid values and old
  entries without the field loading as forward.
- Gateway rendering: forward entries stay in `preauth`, input entries in
  `preauth_input`, ban drop first, TCP/UDP with and without destination, no
  `ct status dnat`, no `preauth_nat` for input, LAN-only/WAN-only/no-interface
  behaviour, and the chain's add/flush bookkeeping.
- Template: `preauth_input` is declared and jumped from `chain input` after
  `jump block` and before the portal/SSH rules.
- UI: `Irány`/`Direction`/`Richtung` label, pre-auth direction select, and
  `Domain (proxy)` no longer inside the direction select; HU/EN/DE strings.

### [3.16.0] - 2026-10-22

#### Added

- **Message of the day (MOTD) after sign-in.** An admin can set a notice in
  **Admin → Settings → Daily notice (MOTD)** with multiline text and either
  a permanent validity or an expiry datetime (`motd_text`, `motd_expires_at`
  in `firewall-settings.json`). Empty text disables it; a past expiry simply
  means inactive. The server includes `motd` only in the authenticated
  `/api/status` payload (and the no-TOTP login response), never for
  unauthenticated, pending or banned callers, and never after expiry.
- **Styled modal on the access screen.** The portal shows a themed modal with
  HU/EN/DE title and close button after login, before access selection. It
  stays until closed, is not repeated by the 30-second status poll, and
  reappears on the next sign-in. The notice text is rendered with
  `textContent`, not `innerHTML`.
- **Settings validation and audit.** Text is stripped and limited to 2000
  characters; the expiry must be an ISO-8601 datetime with a time zone and is
  stored normalized to UTC. A save does not touch nftables; the audit entry
  records only the text length and expiry, not the text.
- **Tests:** settings-store validation, persistence and expiry; admin HTTP
  save, authenticated/unauthenticated visibility, expired and permanent
  notices, clearing via empty text, invalid datetime rejection and audit
  fields; static UI/translation checks and a Node test proving that the modal
  renders, closes, is not re-opened by a status poll and reappears after a new
  login.

### [3.15.2] - 2026-10-22

#### Fixed

- **Domain chips disappeared after an Admin → Access tab round trip.** The
  session summary rendered domains from the response's `hosts` field, while
  `renderAuth` — the client state that caches the active grant — copied only
  `grant`, `grants` and the selected rules. The Admin → Access tab handler
  rebuilds the view from that cached state (`showSession({ ...auth, ... })`),
  so after the round trip the ports (stored in `grant`/`grants`) survived but
  the domains vanished. `renderAuth` now persists `hosts` as part of the auth
  state, so the cached renders (the tab switch and `cachedAccessPayload`) keep
  the domain chips and the countdown intact.
- **Tests:** a Node regression renders the session summary for a grant with
  both ports and domains, replays the Admin → Access tab handler, and asserts
  that the chips and the expiry are identical; a domains-only grant and an
  empty grant are covered too.

### [3.15.1] - 2026-10-22

#### Fixed

- **Upgrade crash-loop during the 3.14.0 interval migration.** The
  container entrypoint validated the rendered ruleset with `nft -c` before
  the interval-flag migration, so on an upgrade the old sets without
  `flags interval` made the check fail (`existing set lacks interval flag`,
  on the VM: `Could not process rule: File exists`). The container then
  crash-looped, the migration never ran, and the `input` chain stayed
  `policy drop` without rules, locking the host out on every port,
  including the portal. The entrypoint now detects the old sets and
  recreates the table **before** validation: it applies the boot table
  (`deploy/dropjak-boot.nft`, now also shipped in the image) first,
  saves the `host_service_*` ports, deletes the old table, and removes the
  boot table only after the final ruleset has loaded. If validation or the
  final load fails after the delete, the host stays fail-closed under the
  boot table and the script exits with a clear Hungarian error. The native
  installer (`install.sh`) follows the same order.
- **Tests:** a namespace regression builds an old-style table (sets
  without `flags interval`), proves that validation fails against it, runs
  the real migration function and asserts every set has `flags interval`
  afterwards; a packaging test pins the ordering (boot guard, then delete,
  then `nft -c`) in both scripts.

### [3.15.0] - 2026-10-22

#### Added

- **Admin user preview.** The Users tab rows (including pending requests)
  have an **Előnézet / Preview / Vorschau** button that opens the selected
  user's portal access screen with the existing portal renderer in
  read-only mode: direct, group and collector rules, domains, TTL limits,
  and TOTP/approval status. The top banner reads `Előnézet: <user>`; every
  action control (rule cards, TTL input, grant and sign-out buttons) is
  disabled. It is not impersonation: no session is created, no nft grant is
  opened, and opening it writes an `admin_user_preview` audit entry.
- **`GET /api/admin/preview?user=<name>`** is protected by `_admin_guard`
  and the origin check; non-admins, cross-origin requests and unknown users
  are rejected.

#### Tests

- Admin guard, cross-origin rejection, preview payload equality with the
  real `/api/status` data for the same user, the audit entry, and proof that
  no session and no nft command is created by opening the preview.

### [3.14.0] - 2026-10-22

#### Added

- **Port ranges in rules.** Rule TCP/UDP fields accept single ports, ranges
  and mixed lists (`22, 80, 8000-8100`, `25565, 27000-27015`) for forward
  and input rules. Input validation reports malformed or reversed ranges
  in HU/EN/DE, stores ranges as `lo-hi` while old integer lists still load,
  merges overlaps, and rejects reserved ports (for input, the portal port
  `8100`) even when they are covered by a range. TCP 22 remains a valid
  explicit host rule port.
- **Interval nft sets.** `allowed_tcp/udp`, `allowed_input_tcp/udp` use
  `flags interval,timeout`, and `host_service_tcp/udp` uses
  `flags interval`. Grant and revoke reconcile overlapping intervals:
  a narrower grant does not shorten or delete a wider active range, and a
  partial revoke re-adds the surviving parts with their remaining TTL.
  `host_service_*` sync only adds uncovered intervals; pruning leaves range
  elements alone.
- **UI and search** show `TCP 8000–8100`; the rule search matches a port
  inside a range (`8050`).
- **Startup migration.** When the old sets lack the interval flag, the
  container entrypoint and the native installer recreate the firewall
  table after validating the new ruleset. The entrypoint saves the
  `host_service_*` members first and restores them, so existing host
  connections stay guarded.

#### Tests

- Unit coverage for range parsing, merging, storage round-trip, reserved
  ports, overlap-safe grant/revoke, service-set ranges and firewall labels.
- `unshare -rn nft -c` syntax check, a real interval+timeout set, and a
  packet-level TCP/UDP test: `18000-18010` allows `18005`, blocks `18011`,
  and blocks `18005` after revocation.

### [3.13.0] - 2026-10-22

#### Changed

- **Proxy tab help:** the Minecraft / Simple Voice Chat example is gone;
  the collapsible box is now called *Information* and keeps only the generic
  Input (127.0.0.1 target) and SNAT notes. The label placeholder is `SSH`.
- **Logs event filter** is a searchable multi-select: a button opens a
  panel with a search field (accent-insensitive), the event types grouped
  by prefix (sign-in and access, Proxy, 2FA, sessions, fail2ban and
  firewall, administration, command line, control channel, service, other),
  checkboxes, and *Mind* / *Egyik sem* buttons that act on the visible
  (filtered) items. Selected events are shown as removable chips. Arrow
  keys move between the search field and the items, Enter toggles an item
  (in the search field it applies), Escape or a click outside closes the
  panel and applies a changed selection. The Drop log has no reason or
  category selector, so it is unchanged.
- **Log scrolling stays put.** In Logs and Drop log the automatic
  refresh no longer redraws while the list is scrolled away from its top,
  hovered or has selected text: new rows are held back and a sticky
  *N new entry — show* button appears (it takes no layout space).
  Clicking it shows the new rows and scrolls to the top of the list. At
  the top the list updates as before. Redraws now keep the inner scroll
  position of the Drop log table (it used to jump back to the top every
  5 seconds), and a manual refresh while scrolled keeps the first visible
  row in place.

#### Added

- **Clickable proxy hostnames** (`https://<host>/`, new tab, `noopener
  noreferrer`, only for valid DNS names): Rules tab domain summaries, the
  rule editor's proxy picker (a separate external-link icon next to each
  entry, so clicking the entry still only toggles it), the portal's active
  session screen, the Domains tab full hostname, the Sessions tab and the
  host of proxy events in Logs. The rule cards on the portal's access
  selection screen are buttons, so they stay plain text there.
- **Copy button** next to each full hostname on the Domains tab
  (clipboard API with a hidden-textarea fallback, short *Copied*
  feedback).
- `GET /api/admin/logs`: `events=` exact multi-event filter (see the
  audit-log section). A single `event=` behaves as before.

### [3.12.0] - 2026-10-22

#### Changed

- **Redesigned Rules admin tab.** The wide table (ID, name, ports, two TTL
  columns, three text buttons per row) is replaced by compact rule cards
  grouped by type (Forward, Input, Domain, Collection, Full access), sorted
  by name. Each card shows the name, a colour-coded type badge and the ID,
  a one-line summary (ports per protocol such as `TCP 22, 80` `UDP 53`,
  shortened with `+N`; the first proxy hostnames; or the names of the
  collection's member rules), the default and maximum duration, and
  Edit / Duplicate / Delete actions (the latter two as icon buttons with
  accessible labels). Descriptions are cut to one line; the full text is
  shown on hover and expands on click.
- The rule editor opens inline in place of the edited card (a new rule at
  the top of the list) and is grouped into Basics, Ports / Domains /
  Included rules, and Duration sections; the collection hints are shown
  only for collection rules. Validation errors appear inside the editor,
  and Escape closes it. Field labels are bound to their inputs.
- Phone width: the toolbar and cards stack; no horizontal scrolling.

#### Added

- **Search and type filter on the Rules tab.** Live, client-side search,
  ignoring case and accents, over name, ID, description, ports, protocol,
  direction, type, proxy hostnames and collection members (ID and name).
  Multiple words must all match. Type filter chips show per-type counts,
  and a result count is shown. Escape clears the search, Enter jumps to the
  first result. The filter is remembered in the browser (localStorage)
  where available. Empty and "no results" states are shown.

### [3.11.1] - 2026-10-22

#### Fixed

- **Port proxy Input entries to loopback-only services did not work.** The
  rule was `redirect to :<target>`, which rewrites the destination to the
  incoming interface's address (the WAN or LAN IP). A service bound only to
  127.0.0.1 (for example a Docker port published as `127.0.0.1:8081`) does
  not listen there, so the kernel answered every SYN with a RST (live trace:
  `<test-domain>:8084` -> RST|ACK from `<test-vm>:8081`, although
  the client had the `(ip . 8084)` input grant). When every socket on the
  target port is bound to 127.0.0.0/8, the rule is now
  `dnat ip to 127.0.0.1:<target>`, for TCP and UDP. Wildcard listeners keep
  `redirect` (a wildcard UDP server replies from the interface address).
  Client IP and authorization (`ct original proto-dst` = listen port) are
  unchanged.
- The portal re-checks the target sockets and `route_localnet` every 10 s
  and atomically re-renders the port proxy chains when the choice changes
  (for example after a reboot where Docker publishes the port after the
  portal starts), flushing the affected listen ports' conntrack entries.
  Settings saves and this refresh share one lock.

#### Added

- `loopback_guard` chain (prerouting, priority raw) in the main and the boot
  nftables tables: drops every packet with a 127.0.0.0/8 destination or source
  that arrives on a non-loopback interface, before NAT. This makes
  `route_localnet` safe and also blocks direct LAN access to Docker
  `127.0.0.1` publications.
- `docker/setup-host.sh` sets `net.ipv4.conf.all.route_localnet = 1` (in
  `/etc/sysctl.d/90-dropjak.conf` and live). Without it the proxy keeps
  `redirect`, and saving shows a warning for the affected entries (HU/EN/DE).
- Proxy tab hint about loopback-only targets and the docker-proxy address.
- Tests: loopback detection, route_localnet, rule choice and refresh unit tests;
  `tests/test_portproxy_netns.py` runs a packet-level test in an
  unprivileged user+net namespace (WAN and LAN clients, TCP/UDP, input and
  forward, targets bound only to 127.0.0.1, the old `redirect` reproduced as
  RST, and the guard against a spoofed 127.0.0.1 frame);
  `tests/portproxy_e2e_vm.py` is the live VM check. 728 tests.

### [3.11.0] - 2026-10-22

#### Added

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

#### Changed

- The forward chain's LAN MAC checks for port grants match the original
  direction only (`ct direction original`). Replies from a LAN DNAT target
  were dropped as a MAC mismatch.

### [3.10.0] - 2026-10-22

#### Fixed

- Turning off **Automatic certificate (Let's Encrypt)** (`proxy_acme`) now
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

#### Added

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

### [3.9.1] - 2026-10-22

#### Changed

- Proxy challenge page: the `sus.png` image is shifted 8px to the left so it
  lines up with the captcha box.

### [3.9.0] - 2026-10-22

#### Added

- Challenge trigger `burst` (**Sok frissítés / spam**): when the same IP
  opens a page of the entry host 10 times within 30 seconds, a new
  challenge is required (a pass issued before the detection no longer
  counts). Only page opens are counted, in portal memory per IP and host.

### [3.8.1] - 2026-10-22

#### Changed

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

### [3.8.0] - 2026-10-21

#### Added

- Per-entry **Challenge (ellenőrzés)** for the domain proxy: a collapsible
  part of each entry card on the Domains tab with triggers `always`,
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
  `proxy_challenge_failed` (warning), labelled in the Logs event filter.
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
- Logs: **IP address / CIDR** filter (`ip=` on `/api/admin/logs`, single
  IPv4/IPv6 address or CIDR, invalid → 400), matching `ip`, `target`,
  `target_ip`, `session_ip` and `request_ip`. Proxy events show `host` +
  `path` (domain/certificate settings changes: domains or root) as the first,
  bold detail line; `visibility`, `triggers` and `unknown_host` are listed
  in the details.
- README and `deploy/HELYI-UTMUTATO.md` (now [section 2](#telepites)): DNS prerequisites for domains (A
  `<root>` and `*.<root>`, DNS only, no AAAA, wildcard certificate for the
  unknown-subdomain challenge).

#### Changed

- `docker-compose.yml` mounts the host's `/etc/localtime` read-only into the
  portal container, so the `daily` challenge trigger uses the host's local
  midnight instead of UTC.

### [3.7.0] - 2026-10-21

#### Added

- New fail2ban signal **Proxy: unauthorized requests**: every 401 that
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
  restored on start, listed in the Fail2ban tab as `proxy` ("HTTP/HTTPS
  only"), and can be lifted on their own (`unban` with
  `"proxy": true`); `unban_all` lifts both kinds. They coexist with a full
  ban on the same IP. A proxy-banned IP also gets 401 from
  `/api/proxy/auth`, and further 401s are not counted.
- Admin → Settings → **Domain settings**: toggle **Automatic certificate
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
- Drop log row `reason=proxy-unauthorized` (category **Proxy: unauthorized**)
  for every proxy 401, rate-limited to 30/min. It does not feed the
  drop-count / distinct-port fail2ban signals.

#### Changed

- `proxy_banned_v4` is listed in the firewall snapshot and flushed on start
  with the other dynamic sets (the ban list is then restored).

### [3.6.0] - 2026-10-21

#### Added

- Multiple proxy root domains: `proxy_domains` (up to 16 unique FQDNs;
  empty list = proxy off) replaces the single `proxy_domain`. Every entry
  has a `root` that must be one of them; an entry is identified by its full
  hostname `<name>.<root>`, so the same subdomain may exist under several
  roots. An entry whose hostname equals a root is rejected, and a root that
  still has entries cannot be deleted (400) until they are removed or moved.
- Admin → **Domains**: a root-domain list (add/remove rows); each entry
  card has a root-domain picker next to the subdomain. The cards use two
  lines (subdomain, root, full hostname, visibility, active, delete / type,
  IP, port).
- Entry `visibility`: `private` (default; entries without it load as
  private) or `public`. A public enabled entry passes `/api/proxy/auth` for
  any client IP that is not fail2ban-banned, without a session or rule. UI:
  "Private / Public" selector on the entry card; the domain-rule picker
  marks public entries "(public)".
- The portal is served over HTTPS on every root domain
  (`https://<root>/`): `/api/proxy/auth` returns `X-Dropjak-Upstream:
  127.0.0.1:<PORT>` for a root (and 404 when the original URI is under
  `/api/proxy/`). A loopback peer with a root `Host` passes the portal host
  check and gets a `Secure` session cookie.

#### Changed

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

#### Migration

- On load, a legacy `proxy_domain` becomes a one-item `proxy_domains` and
  entries without `root` get it; the old key disappears on the next write.
  Legacy entries without any root were inert and are dropped (logged).
- Domain rules with bare entry names are rewritten to `<name>.<legacy root>`
  when the rules are loaded (backup `rules.json.domains-backup-*`). Without a
  legacy root a bare name is dropped from the rule and logged (a rule left
  with no entry is skipped); the rules file is neither quarantined nor
  rewritten by this.

### [3.5.0] - 2026-10-21

#### Added

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

#### Changed

- `/api/proxy/auth` allows a request only if the client IP's active,
  authorized session selected a domain rule listing the requested entry
  (`SessionManager.allows_domain`, replacing `has_authorized_session`).
  Full-access rules and admins get no bypass.
- The proxy configuration moved from Settings to its own admin tab
  **Domains** (Domains), next to Rules.
- Referential integrity: a domain rule may only reference existing entries,
  and an entry referenced by a domain rule cannot be deleted or renamed
  (400). Rule writes and proxy saves are serialized by the admin lock.
- Rule create/update/duplicate audit events carry `domains`; access
  grant/modify events carry the selected `hosts`.

### [3.4.0] - 2026-10-21

#### Added

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

### [3.3.1] - 2026-10-21

#### Fixed

- The ban duration is a shared setting again: it sits in a non-toggle
  **Common settings** group together with the drop window, so turning
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

### [3.3.0] - 2026-10-21

#### Added

- Fail2ban's three monitored signals now have their own checkbox in
  Admin → Fail2ban: failed sign-ins, dropped packets, and distinct
  destination ports. Each one can be switched on or off independently.
- The settings form separates the three signals into bordered groups with
  short hints. A group's numeric fields are disabled while its checkbox is
  unchecked, but their values stay in the form draft and are saved.
- The two drop metrics share the drop window, shown once with a hint that
  both metrics use it.

#### Changed

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

#### Removed

- The `0 = disabled` threshold mechanism. `drop_max` and `drop_ports` must
  be at least 1; `validate_config`/`configure` reject 0 with a range error,
  and `HV_FAIL2BAN_DROP_MAX=0` / `HV_FAIL2BAN_DROP_PORTS=0` fall back to
  the defaults instead of disabling a metric.
- The drop master checkbox in the admin settings form. Persisted legacy
  state with a zero threshold is migrated on load: the affected metric is
  switched off and its threshold reset to the default, without wiping the
  rest of the configuration.

### [3.2.1] - 2026-10-21

#### Fixed

- The access-duration field shows the "hour" unit label again next to the
  number input; durations remain whole hours.
- The multi-selection duration hint no longer repeats the selected rule
  labels in the "upper limit" list when every selected rule is binding.

### [3.2.0] - 2026-10-21

#### Added

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
- The **Logs** tab has an **Event** picker built from the known event
  codes and their localized labels, so event filtering no longer requires
  typing the raw code.

#### Changed

- The audit `event` filter is case- and separator-insensitive
  (`access_granted`, `ACCESS-GRANTED` and `access granted` match the same
  rows), while a partial raw code such as `admin_` still matches that whole
  family. The free-text (`q`) filter now searches values only, not JSON key
  names, and also matches the normalized form of a value; `q=event` no
  longer matches every row.

#### Fixed

- The authorized portal refreshes the rule catalog from `/api/status`
  instead of keeping the snapshot captured at sign-in. An administrator's
  edit is visible on the next poll, and **Modify** fetches a fresh status
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

#### Security

- The fail2ban event store holds only events that can contribute to an
  active metric, and an inactive metric cannot trigger a ban. Turning a
  metric off never extends or lifts an existing ban.
- Live rule propagation remains fail-closed: the affected selection is
  revoked at the commit point, and the changed definition is granted only
  by a new explicit authorization.

### [3.1.0] - 2026-10-21

#### Added

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

#### Changed

- `Session` stores `rules: tuple[str, ...]` and
  `rule_parts: tuple[RuleSelection, ...]`; `rule`/`rule_label` remain the
  first-selection compatibility view. `snapshot()` exposes
  `selected_rules`, `selected_rule_labels` and per-direction `grants`.
- `revoke_rule` is now partial for multi-selection sessions; a session that
  selected only that rule is still removed entirely.
- An admin rule update revokes the rule and its dependent collections in
  one pass (`revoke_rules`), so a session is updated once instead of twice.

#### Fixed

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

#### Security

- Multi-rule and partial-revoke paths are fail-closed: any firewall failure
  drops the session and revokes the old union (queued for retry where
  applicable), and HTTP returns 503.
- Every selected rule ID is resolved before authorization, so a failed
  lookup cannot leave a partial grant.
- Host SSH is still available only through an explicitly assigned input
  rule that lists TCP 22; full grants never open host SSH, and selection
  remains two-phase.

#### Tests

- 517 unit tests pass. New coverage includes multi-selection union and
  overlap, exact grant subtraction, conntrack direction handling, expired
  partial revocation, one-pass `revoke_rules` revocation and lock scope.

#### Documentation

- `docs/propagation-matrix.md` (now [section 3.5](#propagacios-matrix)) section 8 now describes the implemented
  multi-selection behavior, its tests and the residual runtime assumptions.

### [3.0.2] - 2026-10-20

#### Fixed

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

#### Changed

- `HV_FIREWALL_WATCHDOG` can disable the entrypoint firewall watchdog, and
  `HV_ALLOW_STALE_GRANTS_ON_START` is passed through by `docker-compose.yml`;
  both are documented in `.env.example`.

#### Tests

- New revocation, lock-scope, host-service-guard and atomic-chain tests; the
  block generator now rejects out-of-range ports and IPv6 destinations; admin
  update rollback, CLI group cleanup and post-login ban checks are covered.
- `tests/e2e_vm.py` gains gated live scenarios for the revocation matrix,
  natural expiry, block precedence, CLI propagation and restart behaviour.

#### Documentation

- `docs/propagation-matrix.md` (now [section 3.5](#propagacios-matrix)) describes the final runtime behaviour of every
  administrative mutation path, including the residual runtime assumptions.

### [3.0.1] - 2026-10-20

#### Fixed

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

#### Documentation

- README documents the native systemd layout, the copied files and the
  placeholder defaults; `deploy/hv` is documented as a Docker-only helper
  that `install.sh` does not install. Remaining pre-3.0.0 `admin-full`
  wording was removed from the docs.

### [3.0.0] - 2026-10-20

#### Removed

- The built-in `admin-full` rule. It is no longer returned by any API or
  effective-rule calculation, cannot be created, edited, duplicated,
  deleted, assigned or used as a collection member. The identifier itself
  stays permanently reserved so old data cannot resurrect hidden access.
- The dedicated `host_ssh_v4` nftables set, its MAC checks, its accept rule
  and every `host_ssh` plumbing method. Host SSH now uses only the ordinary
  `allowed_input_tcp` pair `(IP, 22)` granted by an assigned host rule.
- The `builtin_rule` field from `/api/admin/state` and the built-in rule
  notice from the admin UI.

#### Changed

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

#### Security

- A stale `admin-full` key or assignment in persisted JSON cannot grant
  access; the value is normalized and filtered before rule resolution and
  never appears in status, admin state or firewall output.
- The legacy rules fallback for unassigned non-admin accounts is forward-only
  and cannot grant host (input) access without an explicit assignment.

### [2.10.0] - 2026-10-20

#### Added

- Configurable firewall/site name (`site_name` in `firewall-settings.json`,
  editable under **Admin → Settings → Firewall name**). It is shown in the
  portal header and browser title and is used as the TOTP issuer/label for
  new authenticator enrollments; empty falls back to `HV_TOTP_ISSUER` /
  `Dropjak`.
- Loud lockout warnings before the nftables rules are loaded and in the
  server log when no enabled admin account exists, because host SSH is
  closed without an active, authorized portal session.

#### Changed

- The Settings page can rename this Dropjak instance without touching
  nftables. The change applies immediately to the UI and to new TOTP
  enrollments; existing authenticator entries keep their old issuer.
- Documentation clarifies that host SSH requires an admin-created host
  (input) rule that explicitly opens TCP 22; UDP 22 is an ordinary host-rule
  port and does not open SSH.

### [2.9.0] - 2026-10-20

#### Added

- Version tracking: `VERSION`, `CHANGELOG.md` (now [section 7](#valtozasnaplo)), the version shown in the
  portal footer, and the `version` field in `/api/status`.

#### Changed

- Host (input) rules may now open TCP or UDP port 22. Only port 8100
  (portal) remains reserved by both validation and the kernel host accept.
- The established-SSH guard accepts a source while it is either in
  `host_ssh_v4` (built-in `admin-full`) or has the `(IP, 22)` pair in
  `allowed_input_tcp` (host rule).
- The generic host-revocation guard excludes TCP 22 so the two SSH routes can
  coexist; UDP 22 remains an ordinary host-rule port.
- Documentation updated for the new host-rule policy, the two SSH routes and
  versioning.

#### Security

- Host rules are still admin-only, and custom full-access rules and full
  collection members never grant access.
- The built-in `admin-full` rule keeps using the dedicated `host_ssh_v4` set;
  a collection can grant 22 only through an input member that explicitly
  lists it.

### [2.8.0] - 2026-10-20

#### Added

- Mixed-direction collections without their own direction: each member grants
  access in its own direction.

#### Changed

- Firewall enforcement uses the directional grants of collection members
  rather than the display union.

### [2.7.0] - 2026-10-20

#### Added

- Forward/input direction for rules; host rules use the `allowed_input_*`
  sets.
- Audit logging for authentication and administrative operations.

#### Security

- Host rules are limited to explicit TCP/UDP ports: full access, ICMP and
  service lists are rejected. At this release both port 22 and port 8100 were
  rejected for host rules.

### [2.6.0] - 2026-10-20

#### Changed

- Rule and access durations are expressed in whole hours; grants can last up
  to 30 days.

### [2.5.0] - 2026-10-20

#### Added

- Collection rules, rule duplication and a random password generator.

#### Changed

- Host SSH is gated to the built-in `admin-full` rule; the configurable host
  SSH policy was removed.

#### Security

- Collections contain 1–64 single-level members and never grant full access.

### [2.4.0] - 2026-10-20

#### Added

- Optional per-user TOTP two-factor authentication with QR enrollment.
- Self-service account requests with admin approval.

#### Changed

- Settings cleanup: blocked destinations were removed from the UI.

### [2.3.0] - 2026-10-20

#### Changed

- Design de-slop: type scale, flat surfaces, contrast and pills.
- The pre-de-slop snapshot was kept in `docs/`.

### [2.2.0] - 2026-10-20

#### Added

- fail2ban login protection and ban management.
- Ban screen for blocked clients.
- Port-scanner and bot bans based on dropped traffic.
- Drop-log source/destination split, six reason groups and post-ban hit
  display.

#### Fixed

- Manual ban visibility, admin session races and dark-theme rule-name
  contrast.

### [2.1.0] - 2026-10-20

#### Added

- Spoofing and portal-bypass hardening.
- NFLOG drop logging.
- Custom firewall rules, raw and visual firewall views, and a drop-log chart.
- Pre-auth any-destination support and published WAN ports.
- Dark theme and SVG icons.

#### Fixed

- NFLOG netlink byte order and flush batching.

### [2.0.1] - 2026-10-19

#### Fixed

- The admin form keeps its values after validation errors.

#### Changed

- Plain "Dropjak" tab title.
- README rewrite: English, Docker-only installation.

### [2.0.0] - 2026-10-19

#### Added

- Initial release: nftables captive portal, Docker host networking,
  trilingual UI, users/groups/rules, two-phase login/authorization,
  fail-closed forwarding and an admin panel.
