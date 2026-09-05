#!/usr/bin/env bash
# Приёмочный тест: развернуть оба сервиса с нуля и убедиться, что они не просто
# поднялись, а реально работают.
#
# Проверяет ровно те два класса отказов, которые в 2026-09 стоили нескольких
# дней разбирательств:
#   1. REALITY-хендшейк не проходит (баг XTLS/Xray-core#6356 с www.microsoft.com) —
#      панель при этом рапортует "xray_running: true";
#   2. перехваченный трафик не доходит до xray (cascade-in на 127.0.0.1) —
#      каскад числится running, счётчики по нулям.
# Отсюда принцип: успехом считается только реально прошедший трафик.
#
# Использование:
#   tests/smoke.sh                       # оба сервиса, образы :latest
#   tests/smoke.sh --relay-only
#   tests/smoke.sh --panel-only
#   RELAY_IMAGE=... PANEL_IMAGE=... tests/smoke.sh
#
# Работает на bridge-сети с портами из диапазона 291xx, поэтому безопасен
# на хосте, где эти же сервисы уже крутятся в бою.

set -euo pipefail

RELAY_IMAGE="${RELAY_IMAGE:-vbif666/noisefloor-vless-reality:latest}"
PANEL_IMAGE="${PANEL_IMAGE:-vbif666/noisefloor-amneziawg-panel:latest}"

RELAY_PANEL_PORT=29101
RELAY_VLESS_PORT=29143
PANEL_PORT=29100

WORKDIR="$(mktemp -d /tmp/noisefloor-smoke.XXXXXX)"
FAILED=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }

pass() { green "  ✓ $*"; }
fail() { red   "  ✗ $*"; FAILED=1; }

cleanup() {
    dim "  очистка…"
    for d in "$WORKDIR"/relay "$WORKDIR"/panel; do
        [ -d "$d" ] && (cd "$d" && docker compose down -v >/dev/null 2>&1 || true)
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# wait_for <секунд> <команда...> — ждём, пока команда не вернёт успех
wait_for() {
    local deadline=$(( $(date +%s) + $1 )); shift
    until "$@" >/dev/null 2>&1; do
        [ "$(date +%s)" -ge "$deadline" ] && return 1
        sleep 1
    done
}

# ---------------------------------------------------------------- релей ----

test_relay() {
    echo
    echo "VLESS-REALITY релей  ($RELAY_IMAGE)"
    local dir="$WORKDIR/relay" c=smoke-vless-reality
    mkdir -p "$dir/data"

    cat > "$dir/docker-compose.yml" <<EOF
services:
  relay:
    image: $RELAY_IMAGE
    container_name: $c
    restart: "no"
    ports:
      - "127.0.0.1:$RELAY_VLESS_PORT:8443"
      - "127.0.0.1:$RELAY_PANEL_PORT:8001"
    environment:
      LABEL: "smoke-test"
      APP_CODENAME: "SmokeTest"
      PUBLIC_HOST: "203.0.113.10"
    volumes:
      - ./data:/data
EOF

    (cd "$dir" && docker compose up -d >/dev/null 2>&1)

    if ! wait_for 45 test -s "$dir/data/INITIAL_ADMIN_PASSWORD.txt"; then
        fail "контейнер не сгенерировал пароль администратора за 45с"
        docker logs "$c" 2>&1 | tail -20
        return
    fi
    pass "поднялся и сам сгенерировал ключи и пароль"

    local pw auth
    pw="$(tr -d '[:space:]' < "$dir/data/INITIAL_ADMIN_PASSWORD.txt")"
    auth="admin:$pw"

    if ! wait_for 30 curl -fsS -u "$auth" "http://127.0.0.1:$RELAY_PANEL_PORT/api/status"; then
        fail "панель не отвечает на /api/status"
        return
    fi
    pass "панель отвечает и требует авторизацию"

    if curl -fsS -o /dev/null "http://127.0.0.1:$RELAY_PANEL_PORT/api/status" 2>/dev/null; then
        fail "панель отдаёт статус БЕЗ авторизации"
    else
        pass "без пароля панель не пускает"
    fi

    local status dest
    status="$(curl -fsS -u "$auth" "http://127.0.0.1:$RELAY_PANEL_PORT/api/status")"
    dest="$(printf '%s' "$status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dest"])')"

    # Регрессия на #6356: этот дефолт молча ломает КАЖДОГО реального клиента.
    if [ "${dest%%:*}" = "www.microsoft.com" ]; then
        fail "camouflage dest по умолчанию = www.microsoft.com (баг REALITY #6356)"
    else
        pass "camouflage dest безопасный: $dest"
    fi

    printf '%s' "$status" | grep -q '"xray_running": *true' \
        && pass "xray запущен" || fail "xray не запущен"

    # --- главное: реально ли проходит трафик через VLESS+REALITY ---
    docker exec -i "$c" python3 - <<'PY' >/dev/null
import json
c = json.load(open("/data/creds.json"))
json.dump({
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": 29180, "protocol": "socks",
                "settings": {"udp": False}}],
  "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
      "address": "127.0.0.1", "port": c["vless_port"],
      "users": [{"id": c["uuid"], "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
    "streamSettings": {"network": "tcp", "security": "reality",
      "realitySettings": {"serverName": c["sni"], "fingerprint": "chrome",
                          "publicKey": c["public_key"], "shortId": c["short_id"]}}}],
}, open("/tmp/probe.json", "w"))
PY
    docker exec -d "$c" sh -c "xray run -c /tmp/probe.json > /tmp/probe.log 2>&1"
    sleep 2

    local code
    code="$(docker exec "$c" curl -s -o /dev/null -w '%{http_code}' --max-time 12 \
            -x socks5h://127.0.0.1:29180 https://www.google.com/generate_204 2>/dev/null || true)"
    if [ "$code" = "204" ]; then
        pass "REALITY-хендшейк проходит, трафик идёт насквозь (HTTP $code)"
    else
        fail "трафик через VLESS+REALITY НЕ идёт (получили '$code')"
        dim "--- лог сервера xray ---"; docker exec "$c" tail -15 /var/log/xray/access.log 2>/dev/null || true
        dim "--- лог клиента xray ---"; docker exec "$c" tail -15 /tmp/probe.log 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------- панель ----

test_panel() {
    echo
    echo "Панель AmneziaWG  ($PANEL_IMAGE)"
    local dir="$WORKDIR/panel" c=smoke-amneziawg-panel
    mkdir -p "$dir/data" "$dir/awg_config"

    # Без NET_ADMIN и host-сети: тест не должен трогать сеть хоста, поэтому
    # живое управление интерфейсом выключено — проверяем панель как таковую.
    cat > "$dir/docker-compose.yml" <<EOF
services:
  panel:
    image: $PANEL_IMAGE
    container_name: $c
    restart: "no"
    ports:
      - "127.0.0.1:$PANEL_PORT:8000"
    environment:
      LIVE_MANAGEMENT_ENABLED: "false"
      AUTO_APPLY_ON_START: "false"
      AWG_AUTO_UPDATE_ENABLED: "false"
      AWG_INTERFACE: "awg-smoke0"
      DEFAULT_SERVER_ADDRESS: "10.77.0.1/24"
      DEFAULT_LISTEN_PORT: "51999"
    volumes:
      - ./data:/opt/panel/data
      - ./awg_config:/etc/amnezia/amneziawg
EOF

    (cd "$dir" && docker compose up -d >/dev/null 2>&1)

    if ! wait_for 60 test -s "$dir/data/INITIAL_ADMIN_PASSWORD.txt"; then
        fail "контейнер не сгенерировал пароль администратора за 60с"
        docker logs "$c" 2>&1 | tail -20
        return
    fi
    pass "поднялся, создал БД и пароль администратора"

    local pw token
    pw="$(grep -oE '[A-Za-z0-9_-]{12,}' "$dir/data/INITIAL_ADMIN_PASSWORD.txt" | head -1)"

    if ! wait_for 45 curl -fsS -o /dev/null "http://127.0.0.1:$PANEL_PORT/"; then
        fail "панель не отдаёт страницу входа"
        return
    fi
    pass "страница входа отдаётся"

    token="$(curl -fsS -X POST "http://127.0.0.1:$PANEL_PORT/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$pw\"}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' 2>/dev/null || true)"
    [ -n "$token" ] && pass "вход по сгенерированному паролю работает" \
                    || { fail "не удалось войти сгенерированным паролем"; return; }

    curl -fsS -o /dev/null "http://127.0.0.1:$PANEL_PORT/api/server" 2>/dev/null \
        && fail "API отдаёт настройки сервера БЕЗ токена" \
        || pass "без токена API закрыт"

    local server
    server="$(curl -fsS -H "Authorization: Bearer $token" "http://127.0.0.1:$PANEL_PORT/api/server")"
    printf '%s' "$server" | grep -q '"public_key": *"[A-Za-z0-9+/=]\{40,\}"' \
        && pass "ключи сервера сгенерированы" || fail "ключи сервера не сгенерированы"
    printf '%s' "$server" | grep -q '"address": *"10.77.0.1/24"' \
        && pass "настройки из окружения применились" || fail "настройки из окружения проигнорированы"

    curl -fsS -o /dev/null -H "Authorization: Bearer $token" \
        "http://127.0.0.1:$PANEL_PORT/api/status/traffic-history" \
        && pass "история трафика отдаётся" || fail "история трафика недоступна"

    # Сквозная проверка: создание клиента должно давать импортируемый конфиг.
    local peer
    peer="$(curl -fsS -X POST "http://127.0.0.1:$PANEL_PORT/api/peers" \
        -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
        -d '{"name":"smoke-client"}' || true)"
    if printf '%s' "$peer" | grep -q '"config_text"'; then
        local cfg
        cfg="$(printf '%s' "$peer" | python3 -c 'import json,sys; print(json.load(sys.stdin)["config_text"])')"
        printf '%s' "$cfg" | grep -q '^Jc = ' \
            && pass "клиент создан, обфускация в конфиге есть" \
            || fail "в конфиге клиента нет параметров обфускации"
        printf '%s' "$cfg" | grep -q '^Endpoint = .*:51999' \
            && pass "Endpoint клиента указывает на нужный порт" \
            || fail "Endpoint клиента неверный"
    else
        fail "не удалось создать клиента через API"
    fi
}

# ------------------------------------------------------------------ main ----

echo "NOISEFLOOR · приёмочный тест"
dim "рабочий каталог: $WORKDIR"

case "${1:-}" in
    --relay-only) test_relay ;;
    --panel-only) test_panel ;;
    "")           test_relay; test_panel ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
esac

echo
if [ "$FAILED" -eq 0 ]; then
    green "ВСЁ ЗЕЛЁНОЕ — сервисы разворачиваются с нуля и реально работают"
else
    red "ЕСТЬ ПАДЕНИЯ — деплоить нельзя"
fi
exit "$FAILED"
