# Dropjak — Docker image
#
# A portál és az nftables egy konténerben fut. A konténer a host hálózati
# névterét használja (network_mode: host), különben az nftables-szabályok nem
# a VM forward-láncára vonatkoznának.
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Dropjak" \
      org.opencontainers.image.description="Portálos hálózati belépőkapu nftables alapon" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HV_STATE_DIR=/var/lib/hatarvedelem \
    HV_NFT_TABLE=hatarvedelem \
    HV_NFT_SET=allowed_v4 \
    PORT=8100

# nftables: a szabályok betöltése és a dinamikus halmaz kezelése.
# conntrack: a kilépő kliensek meglévő kapcsolatainak azonnali bontása.
# util-linux: setpriv, amivel a portál nem rootként, ambient képességekkel indul.
# passwd: useradd a rendszerfelhasználóhoz (a slim image nem tartalmazza).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        conntrack \
        nftables \
        passwd \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --user-group \
        --home-dir /var/lib/hatarvedelem \
        --shell /usr/sbin/nologin \
        hatarvedelem \
    && install -d -m 0750 -o hatarvedelem -g hatarvedelem /var/lib/hatarvedelem

WORKDIR /opt/hatarvedelem

COPY gateway.py server.py droplog.py settings_store.py fail2ban.py index.html icon.png blocked.png services.json ./
COPY deploy/hatarvedelem.nft ./deploy/hatarvedelem.nft
COPY docker/entrypoint.sh /usr/local/bin/hatarvedelem-entrypoint

RUN chmod 0755 /usr/local/bin/hatarvedelem-entrypoint \
    && chmod 0755 /opt/hatarvedelem/deploy/hatarvedelem.nft \
    && chown -R root:root /opt/hatarvedelem

# A 80-as port forgalmát az nft redirect irányítja ide; a portál maga nem
# foglalja el a 80-at. PORT=80 is működik a NET_BIND_SERVICE képességgel.
EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import os,urllib.request,sys; p=os.environ.get('PORT','8100'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/status' % p, timeout=3).status == 200 else 1)"]

ENTRYPOINT ["/usr/local/bin/hatarvedelem-entrypoint"]
