# Dropjak — Docker image
#
# The portal and nftables run in one container. The container uses the host's
# network namespace (network_mode: host); otherwise the nftables rules would
# not apply to the VM's forward chain.
#
# The base image is pinned by digest (DJ-20); the tag is kept for
# readability. Update both on purpose with each release (see the "Pinned
# image digests" section of DOKUMENTACIO.md).
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

LABEL org.opencontainers.image.title="Dropjak" \
      org.opencontainers.image.description="Portal-gated network entry gateway on nftables" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HV_STATE_DIR=/var/lib/hatarvedelem \
    HV_NFT_TABLE=hatarvedelem \
    HV_NFT_SET=allowed_v4 \
    HV_PRIV_HELPER=/run/dropjak/helper.sock \
    PORT=8100

# nftables: loading the rules and managing the dynamic set.
# conntrack: immediate teardown of the existing connections of exiting clients.
# iproute2 + wireguard-tools: managing the dropjak0 WireGuard interface and
# the peers (ip link/addr, wg set/show). These, nft and conntrack run only in
# the privileged helper (privhelper.py: root with just CAP_NET_ADMIN); the
# portal holds no network capability and asks the helper over the
# /run/dropjak/helper.sock Unix socket (HV_PRIV_HELPER, also used by
# `docker compose exec` CLI calls). On the /run/dropjak tmpfs the key files
# are 0600 and are deleted immediately after the operation.
# util-linux: setpriv, with which the entrypoint starts the helper (root,
# bounding set NET_ADMIN) and the portal (non-root, empty bounding set).
# passwd: useradd for the system user (the slim image does not contain it).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        conntrack \
        iproute2 \
        nftables \
        passwd \
        util-linux \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --user-group \
        --home-dir /var/lib/hatarvedelem \
        --shell /usr/sbin/nologin \
        hatarvedelem \
    && install -d -m 0750 -o hatarvedelem -g hatarvedelem /var/lib/hatarvedelem

WORKDIR /opt/hatarvedelem

COPY gateway.py server.py privhelper.py droplog.py settings_store.py fail2ban.py tunnel.py index.html icon.png blocked.png unauthorized.png sus.png ok.png services.json VERSION ./
COPY deploy/dropjak.nft ./deploy/dropjak.nft
# The table providing early boot protection: the set-flag migration during an
# upgrade loads it before deleting the old table (fail-closed time window).
COPY deploy/dropjak-boot.nft ./deploy/dropjak-boot.nft
COPY deploy/tunnel-agent ./tunnel-agent
COPY docker/entrypoint.sh /usr/local/bin/dropjak-entrypoint

RUN chmod 0755 /usr/local/bin/dropjak-entrypoint \
    && chmod 0755 /opt/hatarvedelem/deploy/dropjak.nft \
    && chown -R root:root /opt/hatarvedelem

# Port 80 traffic is directed here by the nft redirect; the portal itself does
# not occupy port 80. PORT=80 works too: the entrypoint then keeps the
# NET_BIND_SERVICE capability for the portal (only for a port below 1024).
EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import os,urllib.request,sys; p=os.environ.get('PORT','8100'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/status' % p, timeout=3).status == 200 else 1)"]

ENTRYPOINT ["/usr/local/bin/dropjak-entrypoint"]
