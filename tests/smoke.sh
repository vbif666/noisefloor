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
#   tests/smoke.sh --rules-only
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

# ------------------------------------------------- правила и перехват ----

# Гоняется в контейнере с собственным сетевым стеком (bridge + NET_ADMIN),
# поэтому правила хоста не затрагиваются вообще.
test_rules() {
    echo
    echo "Правила фаервола  ($PANEL_IMAGE)"

    local out
    out="$(docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
        --entrypoint sh "$PANEL_IMAGE" -c '
        set -e
        ip link add awg0 type dummy && ip addr add 10.13.13.1/24 dev awg0 && ip link set awg0 up
        for i in 1 2 3; do
            noisefloor-rules up --iface awg0 --egress eth0 --cascade-port 12345 --mode tproxy >/dev/null
        done
        echo "fwd=$(iptables -S NOISEFLOOR-FWD | grep -c "^-A")"
        echo "fwd_jumps=$(iptables -S FORWARD | grep -c NOISEFLOOR-FWD)"
        echo "nat_jumps=$(iptables -t nat -S POSTROUTING | grep -c NOISEFLOOR-POST)"
        echo "tproxy_tcp=$(iptables -t mangle -S NOISEFLOOR-TPROXY | grep -c "p tcp -j TPROXY")"
        echo "tproxy_udp=$(iptables -t mangle -S NOISEFLOOR-TPROXY | grep -c "p udp -j TPROXY")"
        echo "iprules=$(ip rule list | grep -c "lookup 100")"
        noisefloor-rules down --iface awg0 --egress eth0 >/dev/null
        echo "left=$(iptables-save | grep -c NOISEFLOOR || true)"
        echo "left_iprules=$(ip rule list | grep -c "lookup 100" || true)"
    ' 2>/dev/null)"

    check() {
        local key="$1" want="$2" got
        got="$(printf '%s' "$out" | grep "^$key=" | cut -d= -f2)"
        [ "$got" = "$want" ] && return 0 || { echo "    ($key=$got, ожидалось $want)"; return 1; }
    }

    # Трижды применили — обязана остаться ровно одна копия. Именно этого
    # не было раньше: на проде накопилось по семь комплектов правил.
    if check fwd_jumps 1 && check nat_jumps 1 && check iprules 1; then
        pass "троекратное применение не дублирует правила"
    else
        fail "правила дублируются при повторном применении"
    fi

    check tproxy_tcp 1 && check tproxy_udp 1 \
        && pass "перехват настроен и на TCP, и на UDP (QUIC и DNS в каскаде)" \
        || fail "UDP не перехватывается — QUIC и DNS пойдут мимо каскада"

    if check left 0 && check left_iprules 0; then
        pass "down убирает правила и маршрут метки полностью"
    else
        fail "после down остались следы правил"
    fi

    # Режим redirect — не «то же самое, но без UDP»: у него своя половина
    # правил, и каждая из них закрывает уже случавшуюся поломку.
    out="$(docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
        --entrypoint sh "$PANEL_IMAGE" -c '
        set -e
        ip link add awg0 type dummy && ip addr add 10.13.13.1/24 dev awg0 && ip link set awg0 up
        noisefloor-rules up --iface awg0 --egress eth0 --cascade-port 12345 \
            --mode redirect --block-quic --isolate-clients >/dev/null
        # Служебные сети обязаны обойти каскад РАНЬШЕ правила перехвата.
        # Сравниваем позиции, а не считаем строки: набор исключений ещё
        # будет меняться, и тест не должен ломаться от каждой новой сети.
        echo "last_return=$(iptables -t nat -S NOISEFLOOR-PRE | grep -n "j RETURN" | tail -1 | cut -d: -f1)"
        echo "first_redirect=$(iptables -t nat -S NOISEFLOOR-PRE | grep -n "p tcp -j REDIRECT" | head -1 | cut -d: -f1)"
        echo "quic=$(iptables -S NOISEFLOOR-FWD | grep -c "dport 443 -j REJECT")"
        echo "mss=$(iptables -S NOISEFLOOR-FWD | grep -c TCPMSS)"
        echo "port_closed=$(iptables -S NOISEFLOOR-IN | grep -c "dport 12345 -j DROP")"
        noisefloor-rules down --iface awg0 --egress eth0 >/dev/null
        echo "left=$(iptables-save | grep -c NOISEFLOOR || true)"
    ' 2>/dev/null)"

    local last_return first_redirect
    last_return="$(printf '%s' "$out" | grep "^last_return=" | cut -d= -f2)"
    first_redirect="$(printf '%s' "$out" | grep "^first_redirect=" | cut -d= -f2)"
    if [ -n "$last_return" ] && [ -n "$first_redirect" ] && [ "$last_return" -lt "$first_redirect" ]; then
        pass "служебные сети обходят каскад раньше правила перехвата"
    else
        fail "в redirect-режиме TCP к панели и соседям по туннелю уедет в каскад"
    fi

    check quic 1 \
        && pass "QUIC закрыт отказом — браузер сразу возьмёт TCP" \
        || fail "QUIC уйдёт мимо каскада с настоящим адресом сервера"

    check mss 2 \
        && pass "MSS подрезается в обе стороны" \
        || fail "MSS правится только в одну сторону — крупные загрузки встанут"

    # Две строки: TCP и UDP — порт перехвата закрывается для обоих.
    check port_closed 2 \
        && pass "порт перехвата закрыт для всех, кроме туннеля" \
        || fail "служебный порт каскада виден из интернета"

    check left 0 \
        && pass "down убирает и правила redirect-режима" \
        || fail "после down остались следы правил redirect-режима"
}

# ------------------------------------------------------------------ main ----

echo "NOISEFLOOR · приёмочный тест"
dim "рабочий каталог: $WORKDIR"

case "${1:-}" in
    --relay-only) test_relay ;;
    --panel-only) test_panel; test_rules ;;
    --rules-only) test_rules ;;
    "")           test_relay; test_panel; test_rules ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
esac

echo
if [ "$FAILED" -eq 0 ]; then
    green "ВСЁ ЗЕЛЁНОЕ — сервисы разворачиваются с нуля и реально работают"
else
    red "ЕСТЬ ПАДЕНИЯ — деплоить нельзя"
fi
exit "$FAILED"
