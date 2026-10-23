# Dropjak — Docker image
#
# The portal and nftables run in one container. The container uses the host's
# network namespace (network_mode: host); otherwise the nftables rules would
# not apply to the VM's forward chain.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Dropjak" \
      org.opencontainers.image.description="Portal-gated network entry gateway on nftables" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HV_STATE_DIR=/var/lib/hatarvedelem \
    HV_NFT_TABLE=hatarvedelem \
    HV_NFT_SET=allowed_v4 \
    PORT=8100

# nftables: loading the rules and managing the dynamic set.
# conntrack: immediate teardown of the existing connections of exiting clients.
# iproute2 + wireguard-tools: managing the dropjak0 WireGuard interface and
# the peers (ip link/addr, wg set/show). The portal does not run as root, but
# the entrypoint starts it with the ambient CAP_NET_ADMIN capability (setpriv),
# which is enough to create the interface; on the /run/dropjak tmpfs the key
# files are 0600 and are deleted immediately after the operation.
# util-linux: setpriv, with which the portal starts as a non-root user with
# ambient capabilities.
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

COPY gateway.py server.py droplog.py settings_store.py fail2ban.py tunnel.py index.html icon.png blocked.png unauthorized.png sus.png ok.png services.json VERSION ./
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
# not occupy port 80. PORT=80 works too with the NET_BIND_SERVICE capability.
EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import os,urllib.request,sys; p=os.environ.get('PORT','8100'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/status' % p, timeout=3).status == 200 else 1)"]

ENTRYPOINT ["/usr/local/bin/dropjak-entrypoint"]
