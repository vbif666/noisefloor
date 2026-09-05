# VLESS + Reality endpoint - self-contained, portable image.
# Xray-core binary is fetched from the OFFICIAL XTLS/Xray-core GitHub releases
# at build time (not vendored, not a third-party fork) and checksum-verified.

FROM python:3.12-slim AS xray-fetch
ARG XRAY_VERSION=latest
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/xray
RUN set -eux; \
    if [ "$XRAY_VERSION" = "latest" ]; then \
      TAG=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -m1 '"tag_name"' | cut -d '"' -f4); \
    else \
      TAG="$XRAY_VERSION"; \
    fi; \
    echo "Using Xray-core release: $TAG"; \
    BASE="https://github.com/XTLS/Xray-core/releases/download/${TAG}"; \
    curl -fsSL -o Xray-linux-64.zip "${BASE}/Xray-linux-64.zip"; \
    curl -fsSL -o Xray-linux-64.zip.dgst "${BASE}/Xray-linux-64.zip.dgst"; \
    EXPECTED=$(grep -i '^SHA2-256=' Xray-linux-64.zip.dgst | head -1 | cut -d '=' -f2 | tr -d ' \r'); \
    ACTUAL=$(sha256sum Xray-linux-64.zip | cut -d ' ' -f1); \
    echo "expected=$EXPECTED actual=$ACTUAL"; \
    [ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || (echo "Xray-core checksum verification FAILED"; exit 1); \
    unzip -o Xray-linux-64.zip -d /tmp/xray-out; \
    echo "$TAG" > /tmp/xray-out/VERSION

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates dumb-init && rm -rf /var/lib/apt/lists/*
COPY --from=xray-fetch /tmp/xray-out/xray /usr/local/bin/xray
COPY --from=xray-fetch /tmp/xray-out/VERSION /opt/XRAY_VERSION
RUN chmod +x /usr/local/bin/xray

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ /app/

RUN mkdir -p /data /var/log/xray
VOLUME ["/data"]

ENV DATA_DIR=/data \
    PANEL_PORT=8001 \
    VLESS_PORT=8443 \
    REALITY_DEST=dl.google.com:443 \
    LABEL=vless-reality

EXPOSE 8001 8443

ENTRYPOINT ["dumb-init", "--"]
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PANEL_PORT}"]
