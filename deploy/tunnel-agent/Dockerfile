# Dropjak home-side tunnel agent.
#
# Runs as root inside its own network namespace because it needs NET_ADMIN
# to create wg0 and load nftables rules. The compose blueprint drops every
# other capability, sets no-new-privileges, a read-only rootfs and tmpfs for
# /run and /tmp. The Docker host must provide the WireGuard kernel module.
FROM python:3.12-alpine

RUN apk add --no-cache \
        ca-certificates \
        iproute2 \
        nftables \
        wireguard-tools

COPY agent.py /agent.py
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/agent.py"]
