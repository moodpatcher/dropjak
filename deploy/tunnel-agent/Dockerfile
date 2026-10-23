# Dropjak home-side tunnel agent.
#
# Runs as root inside its own network namespace because it needs NET_ADMIN
# to create wg0 and load nftables rules. The compose blueprint drops every
# other capability, sets no-new-privileges, a read-only rootfs and tmpfs for
# /run and /tmp. The Docker host must provide the WireGuard kernel module.
# The base image is pinned by digest (DJ-20); the tag is kept for
# readability. Update both on purpose with each release.
FROM python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d

RUN apk add --no-cache \
        ca-certificates \
        iproute2 \
        nftables \
        wireguard-tools

COPY agent.py /agent.py
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/agent.py"]
