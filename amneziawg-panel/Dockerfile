# NOISEFLOOR · панель AmneziaWG
#
# Все версии закреплены явно. Обновление — это осознанный коммит с новым
# тегом и пересборка, а не "что там сейчас latest": именно плавающий тег
# однажды притащил Xray с багом REALITY и стоил нескольких дней разбора.
#
# В рантайм-образе нет ни go, ни git, ни компилятора — всё собранное
# приезжает из builder-стадий. Это убирает тулчейн из прода (контейнер
# работает от root с NET_ADMIN) и снимает около гигабайта веса.

ARG GO_VERSION=1.27.1
ARG AWG_GO_REF=v3.1.20260828
ARG AWG_TOOLS_REF=v3.1.20260812
ARG XRAY_VERSION=v26.7.28

# ------------------------ сборка: amneziawg-go + amneziawg-tools ----------
FROM debian:bookworm-slim AS awg-build
ARG GO_VERSION
ARG AWG_GO_REF
ARG AWG_TOOLS_REF

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) goarch=amd64 ;; \
        arm64) goarch=arm64 ;; \
        *) echo "неподдерживаемая архитектура: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tgz; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz
ENV PATH=/usr/local/go/bin:$PATH

WORKDIR /build
RUN git clone --quiet --depth 1 --branch "$AWG_GO_REF" \
        https://github.com/amnezia-vpn/amneziawg-go awg-go \
    && make -C awg-go \
    && test -x awg-go/amneziawg-go
RUN git clone --quiet --depth 1 --branch "$AWG_TOOLS_REF" \
        https://github.com/amnezia-vpn/amneziawg-tools awg-tools \
    && make -C awg-tools/src \
    && test -x awg-tools/src/wg

# ------------------------------------ загрузка xray (с проверкой суммы) ---
FROM debian:bookworm-slim AS xray-fetch
ARG XRAY_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/xray
RUN set -eux; \
    base="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"; \
    curl -fsSL -o Xray-linux-64.zip "${base}/Xray-linux-64.zip"; \
    curl -fsSL -o Xray-linux-64.zip.dgst "${base}/Xray-linux-64.zip.dgst"; \
    expected="$(grep -i '^SHA2-256=' Xray-linux-64.zip.dgst | head -1 | cut -d= -f2 | tr -d ' \r')"; \
    actual="$(sha256sum Xray-linux-64.zip | cut -d' ' -f1)"; \
    echo "xray ${XRAY_VERSION}: ожидалось $expected, получено $actual"; \
    [ -n "$expected" ] && [ "$expected" = "$actual" ]; \
    unzip -oq Xray-linux-64.zip -d /out

# ------------------------------------------------------------- рантайм ---
FROM python:3.12-slim-bookworm
ARG AWG_GO_REF
ARG AWG_TOOLS_REF
ARG XRAY_VERSION

# bash — awg-quick это bash-скрипт; iproute2/iptables/nftables — поднятие
# интерфейса и правила; curl — проверка обновлений и HEALTHCHECK.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl iproute2 iptables nftables procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=awg-build  /build/awg-go/amneziawg-go              /usr/local/bin/amneziawg-go
COPY --from=awg-build  /build/awg-tools/src/wg                 /usr/local/bin/awg
COPY --from=awg-build  /build/awg-tools/src/wg-quick/linux.bash /usr/local/bin/awg-quick
COPY --from=xray-fetch /out/xray                               /usr/local/bin/xray
RUN chmod +x /usr/local/bin/amneziawg-go /usr/local/bin/awg \
             /usr/local/bin/awg-quick /usr/local/bin/xray

# Версии зашитых бинарников видит и панель (показывает в UI), и человек
# через docker inspect — без них "какая у меня версия" превращается в гадание.
ENV AWG_GO_BUILT_REF=${AWG_GO_REF} \
    AWG_TOOLS_BUILT_REF=${AWG_TOOLS_REF} \
    XRAY_BUILT_REF=${XRAY_VERSION} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/panel
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/app     ./app
COPY src/static  ./static
COPY src/manage.py ./manage.py
RUN mkdir -p /opt/panel/data /etc/amnezia/amneziawg

COPY entrypoint.sh /entrypoint.sh
COPY noisefloor-rules /usr/local/bin/noisefloor-rules
RUN chmod +x /entrypoint.sh /usr/local/bin/noisefloor-rules

EXPOSE 8000
VOLUME ["/opt/panel/data", "/etc/amnezia/amneziawg"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS -o /dev/null http://127.0.0.1:8000/ || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
