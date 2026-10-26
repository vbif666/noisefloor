# NOISEFLOOR · fail2ban для хоста
#
# Отдельный сервис рядом с панелью и релеем: читает журнал sshd хоста и
# банит адреса, которые перебирают пароли. Баны кладутся в свою таблицу
# nftables (inet f2b-table) в сети хоста — правила Docker, панели и zapret
# она не трогает.
#
# Версии закреплены явно, как в остальных образах проекта. bookworm, а не
# trixie: таблицу кладёт в ядро nft из контейнера, а читает её потом nft
# хоста. Таблица от nft 1.1 (trixie) роняет segfault-ом nft 1.0.2 из
# Ubuntu 22.04 — и вместе с ним `nft list ruleset` и всё, что его зовёт
# (zapret). От 1.0.6 из bookworm старый nft не падает.

ARG DEBIAN_TAG=bookworm-slim

FROM debian:${DEBIAN_TAG}

ARG FAIL2BAN_VERSION=1.0.2-2
ARG NFTABLES_VERSION=1.0.6-2+deb12u2
ARG BUILD_VERSION=dev
ARG BUILD_SHA=unknown
ARG BUILD_DATE=unknown

# python3-systemd — для хостов без /var/log/auth.log (только journald).
RUN apt-get update && apt-get install -y --no-install-recommends \
        fail2ban="${FAIL2BAN_VERSION}" \
        nftables="${NFTABLES_VERSION}" \
        python3-systemd \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    # Свой набор джейлов вместо дебиановского (там sshd с бэкендом systemd
    # и действиями под iptables).
    && rm -f /etc/fail2ban/jail.d/*.conf

COPY jail.local /etc/fail2ban/jail.local
COPY fail2ban.local /etc/fail2ban/fail2ban.local
COPY sshd.local /etc/fail2ban/filter.d/sshd.local
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

LABEL org.opencontainers.image.title="noisefloor-fail2ban" \
      org.opencontainers.image.source="https://github.com/vbif666/noisefloor" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.revision="${BUILD_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"
ENV NOISEFLOOR_VERSION=${BUILD_VERSION}

VOLUME /var/lib/fail2ban

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD fail2ban-client ping >/dev/null || exit 1

ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]
