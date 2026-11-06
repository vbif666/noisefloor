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
#   tests/smoke.sh --install-only
#   tests/smoke.sh --canary-only
#   tests/smoke.sh --failover-only
#   tests/smoke.sh --mtu-only
#   tests/smoke.sh --ipv6-only
#   tests/smoke.sh --split-only
#   tests/smoke.sh --xudp-only
#   tests/smoke.sh --rotation-only [секунд загрузки, по умолчанию 60]
#   tests/smoke.sh --selfcheck-only
#   tests/smoke.sh --rollback-only
#   tests/smoke.sh --notify-only
#   tests/smoke.sh --fallback-only
#   tests/smoke.sh --telegram-install-only
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
      - "127.0.0.1:$RELAY_VLESS_PORT:443"
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

    local pw jar
    pw="$(tr -d '[:space:]' < "$dir/data/INITIAL_ADMIN_PASSWORD.txt")"
    jar="$(mktemp)"

    if ! wait_for 30 curl -kfsS -o /dev/null "https://127.0.0.1:$RELAY_PANEL_PORT/login"; then
        fail "страница релея не отвечает по HTTPS"
        return
    fi
    pass "страница релея отвечает по HTTPS"

    if curl -fsS -o /dev/null --max-time 5 "http://127.0.0.1:$RELAY_PANEL_PORT/login" 2>/dev/null; then
        fail "страница релея отвечает и по голому HTTP"
    else
        pass "по HTTP страница релея не отдаётся"
    fi

    if curl -kfsS -o /dev/null -u "admin:$pw" "https://127.0.0.1:$RELAY_PANEL_PORT/api/status" 2>/dev/null; then
        fail "релей принимает Basic-авторизацию"
    else
        pass "Basic-авторизация не принимается"
    fi

    curl -kfsS -o /dev/null -c "$jar" --data-urlencode "username=admin" --data-urlencode "password=$pw" \
        "https://127.0.0.1:$RELAY_PANEL_PORT/login" \
        && pass "вход через форму работает" || { fail "вход через форму не прошёл"; return; }

    if curl -kfsS -o /dev/null "https://127.0.0.1:$RELAY_PANEL_PORT/api/status" 2>/dev/null; then
        fail "панель отдаёт статус БЕЗ авторизации"
    else
        pass "без входа панель не пускает"
    fi

    local status dest
    status="$(curl -kfsS -b "$jar" "https://127.0.0.1:$RELAY_PANEL_PORT/api/status")"
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

    if ! wait_for 45 curl -kfsS -o /dev/null "https://127.0.0.1:$PANEL_PORT/"; then
        fail "панель не отдаёт страницу входа"
        return
    fi
    pass "страница входа отдаётся"

    token="$(curl -kfsS -X POST "https://127.0.0.1:$PANEL_PORT/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$pw\"}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' 2>/dev/null || true)"
    [ -n "$token" ] && pass "вход по сгенерированному паролю работает" \
                    || { fail "не удалось войти сгенерированным паролем"; return; }

    curl -kfsS -o /dev/null "https://127.0.0.1:$PANEL_PORT/api/server" 2>/dev/null \
        && fail "API отдаёт настройки сервера БЕЗ токена" \
        || pass "без токена API закрыт"

    local server
    server="$(curl -kfsS -H "Authorization: Bearer $token" "https://127.0.0.1:$PANEL_PORT/api/server")"
    printf '%s' "$server" | grep -q '"public_key": *"[A-Za-z0-9+/=]\{40,\}"' \
        && pass "ключи сервера сгенерированы" || fail "ключи сервера не сгенерированы"
    printf '%s' "$server" | grep -q '"address": *"10.77.0.1/24"' \
        && pass "настройки из окружения применились" || fail "настройки из окружения проигнорированы"

    curl -kfsS -o /dev/null -H "Authorization: Bearer $token" \
        "https://127.0.0.1:$PANEL_PORT/api/status/traffic-history" \
        && pass "история трафика отдаётся" || fail "история трафика недоступна"

    # Сквозная проверка: создание клиента должно давать импортируемый конфиг.
    local peer
    peer="$(curl -kfsS -X POST "https://127.0.0.1:$PANEL_PORT/api/peers" \
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
            noisefloor-rules up --iface awg0 --egress eth0 --cascade-port 12345 --mode tproxy --block-quic >/dev/null
        done
        echo "fwd=$(iptables -S NOISEFLOOR-FWD | grep -c "^-A")"
        echo "fwd_jumps=$(iptables -S FORWARD | grep -c NOISEFLOOR-FWD)"
        echo "nat_jumps=$(iptables -t nat -S POSTROUTING | grep -c NOISEFLOOR-POST)"
        echo "tproxy_tcp=$(iptables -t mangle -S NOISEFLOOR-TPROXY | grep -c "p tcp -j TPROXY")"
        echo "tproxy_udp=$(iptables -t mangle -S NOISEFLOOR-TPROXY | grep -c "p udp -j TPROXY")"
        # Закрытый QUIC обязан обойти TPROXY (стоять раньше перехвата UDP)
        # и упереться в REJECT в FORWARD.
        echo "quic_return=$(iptables -t mangle -S NOISEFLOOR-TPROXY | grep -n "dport 443 -j RETURN" | head -1 | cut -d: -f1)"
        echo "udp_tproxy=$(iptables -t mangle -S NOISEFLOOR-TPROXY | grep -n "p udp -j TPROXY" | head -1 | cut -d: -f1)"
        echo "tproxy_quic=$(iptables -S NOISEFLOOR-FWD | grep -c "dport 443 -j REJECT")"
        echo "iprules=$(ip rule list | grep -c "lookup 20231")"
        noisefloor-rules down --iface awg0 --egress eth0 >/dev/null
        echo "left=$(iptables-save | grep -c NOISEFLOOR || true)"
        echo "left_iprules=$(ip rule list | grep -c "lookup 20231" || true)"
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
        && pass "перехват настроен и на TCP, и на UDP (звонки и DNS в каскаде)" \
        || fail "UDP не перехватывается — звонки и DNS пойдут мимо каскада"

    local quic_return udp_tproxy
    quic_return="$(printf '%s' "$out" | grep "^quic_return=" | cut -d= -f2)"
    udp_tproxy="$(printf '%s' "$out" | grep "^udp_tproxy=" | cut -d= -f2)"
    if [ -n "$quic_return" ] && [ -n "$udp_tproxy" ] && [ "$quic_return" -lt "$udp_tproxy" ] \
        && check tproxy_quic 1; then
        pass "в tproxy QUIC минует перехват и закрыт отказом — браузер сразу возьмёт TCP"
    else
        fail "в tproxy QUIC поедет через каскад поверх TCP и затормозит страницы"
    fi

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

    # Ядро не приняло TPROXY: up обязан упасть, а не притвориться успешным.
    # Подмена iptables-restore вместо настоящего отсутствия модуля: выгружать
    # модули в тесте нельзя, ядро общее с хостом.
    out="$(docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
        --entrypoint sh "$PANEL_IMAGE" -c '
        ip link add awg0 type dummy && ip link set awg0 up
        mkdir -p /tmp/fake
        cat > /tmp/fake/iptables-restore <<STUB
#!/bin/sh
in="\$(cat)"
case "\$in" in *TPROXY*) echo "Extension TPROXY revision 0 not supported" >&2; exit 2 ;; esac
printf "%s\n" "\$in" | /usr/sbin/iptables-restore "\$@"
STUB
        chmod +x /tmp/fake/iptables-restore
        PATH=/tmp/fake:$PATH noisefloor-rules up --iface awg0 --egress eth0 \
            --cascade-port 12345 --mode tproxy >/dev/null 2>&1
        echo "rc=$?"
        echo "fwd_jumps=$(iptables -S FORWARD | grep -c NOISEFLOOR-FWD || true)"
        echo "masquerade=$(iptables -t nat -S | grep -c MASQUERADE || true)"
    ' 2>/dev/null)"

    check rc 1 \
        && pass "без TPROXY up завершается с ошибкой" \
        || fail "сбой TPROXY не виден по коду возврата"

    check fwd_jumps 0 && check masquerade 0 \
        && pass "без перехвата форвардинг наружу не открывается" \
        || fail "перехват не встал, а клиенты всё равно выходят напрямую"
}

# ------------------------------------------------------ канарейка, вживую ----

# Стенд из четырёх контейнеров: релей, панель с настоящим каскадом, канарейка и
# поддельный интернет. Адреса публичные: перехват пропускает приватные сети, а
# xray на релее не ходит и в служебные диапазоны вроде 100.64.0.0/10.
canary_status_has() {
    local body
    body="$(curl -kfsS -H "Authorization: Bearer $CANARY_TOKEN" \
        "https://127.0.0.1:$CANARY_PANEL_PORT/api/server/cascade/status")" || return 1
    [[ "$body" == *$1* ]]
}

canary_field() {
    curl -kfsS -H "Authorization: Bearer $CANARY_TOKEN" \
        "https://127.0.0.1:$CANARY_PANEL_PORT/api/server/cascade/status" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1]) or "")' "$1"
}

# Свежий успешный результат с нужного адреса. Для адреса панели успеха не будет:
# канарейка красная на exit_ip, поэтому смотрим только на адрес.
canary_exits_via() {
    canary_status_has "\"canary_exit_ip\":\"$1\""
}

panel_xray_pid_any() {
    panel_xray_pid
}

sleep_seconds() {
    local until=$(( $(date +%s) + $1 ))
    while [ "$(date +%s)" -lt "$until" ]; do read -r -t 1 <> <(:) || true; done
}

canary_cleanup() {
    docker rm -f smoke-canary smoke-canary-panel smoke-canary-relay smoke-canary-relay2 smoke-canary-web smoke-canary-fb >/dev/null 2>&1 || true
    docker network rm smoke-canary-priv >/dev/null 2>&1 || true
    docker network rm smoke-canary-net smoke-canary-lan smoke-canary-ru >/dev/null 2>&1 || true
}

# Стенд: поддельный интернет, релей 5.5.77.20, панель 5.5.77.30, канарейка.
# Второй аргумент - интервал канарейки. Ошибки возвращает кодом.
canary_stand() {
    local dir="$WORKDIR/$1" interval="$2" c=smoke-canary-panel net=smoke-canary-net
    CANARY_PANEL_PORT=29103
    mkdir -p "$dir/data/canary" "$dir/awg_config" "$dir/relay" "$dir/bin"
    canary_cleanup
    trap 'canary_cleanup; docker rm -f smoke-rules-panel >/dev/null 2>&1 || true; cleanup' EXIT
    docker network create --subnet 5.5.77.0/24 "$net" >/dev/null
    # Канарейка в своей сети: иначе «интернет» был бы ей виден напрямую, мимо туннеля.
    docker network create --subnet 100.64.78.0/24 smoke-canary-lan >/dev/null

    cat > "$dir/web.py" <<'PY'
import os, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = os.urandom(1048576)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_HEAD(self):
        self.remember()
        self.send_response(204)
        self.end_headers()
    def remember(self):
        # Журнал адресов: кто на самом деле дошёл до "интернета". Канарейка про
        # неверный адрес выхода сообщает текстом ошибки, этому журналу проще верить.
        with open("/tmp/seen", "a") as seen:
            seen.write(self.client_address[0] + "\n")
    def do_POST(self):
        # Уведомления: кто прислал и что. Адрес показывает, шло ли через каскад.
        import json
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        with open("/tmp/hook", "a", encoding="utf-8") as hook:
            hook.write(f"{self.client_address[0]} {self.path} {body.get('chat_id', '')} {body['text']}\n")
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def do_GET(self):
        if self.path == "/generate_204":
            self.do_HEAD()
            return
        self.remember()
        if self.path.startswith("/slow/"):
            # Медленная загрузка: 10 КБ в секунду, длительность в адресе.
            seconds = int(self.path.rsplit("/", 1)[1])
            self.send_response(200)
            self.send_header("Content-Length", str(seconds * 10240))
            self.end_headers()
            for _ in range(seconds):
                self.wfile.write(b"x" * 10240)
                self.wfile.flush()
                time.sleep(1)
            return
        body = BODY if self.path == "/1mb" else f"ip={self.client_address[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        data, addr = sock.recvfrom(1500)
        name_end = data.index(b"\x00", 12) + 1
        qtype = int.from_bytes(data[name_end:name_end + 2], "big")
        question = data[12:name_end + 4]
        with open("/tmp/dns-seen", "a") as seen:
            seen.write(f"{qtype} {question.hex()}\n")
        rdata = {1: bytes([5, 5, 77, 10]), 16: b"\x02ok"}.get(qtype)
        answer = b"" if rdata is None else b"\xc0\x0c" + data[name_end:name_end + 4] \
            + b"\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata
        sock.sendto(data[:2] + b"\x81\x80" + data[4:6] + (b"\x00\x01" if answer else b"\x00\x00")
                    + b"\x00\x00\x00\x00" + question + answer, addr)

def udp_echo(port):
    # Отвечает адресом отправителя: так видно, откуда пришёл UDP.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    while True:
        data, addr = sock.recvfrom(1500)
        sock.sendto(addr[0].encode(), addr)

threading.Thread(target=dns, daemon=True).start()
threading.Thread(target=udp_echo, args=(3478,), daemon=True).start()
threading.Thread(target=udp_echo, args=(443,), daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
PY
    docker run -d --name smoke-canary-web --network "$net" --ip 5.5.77.10 \
        -v "$dir/web.py:/web.py:ro" --entrypoint python "$PANEL_IMAGE" /web.py >/dev/null

    docker run -d --name smoke-canary-relay --network "$net" --ip 5.5.77.20 \
        -e LABEL=smoke-canary -e APP_CODENAME=SmokeCanary -e PUBLIC_HOST=5.5.77.20 \
        -e ADMIN_PASSWORD=smoke-relay-pass ${CANARY_RELAY_ENV:-} \
        -v "$dir/relay:/data" "$RELAY_IMAGE" >/dev/null
    if ! wait_for 45 test -s "$dir/relay/creds.json"; then
        fail "релей стенда не поднялся"
        docker logs smoke-canary-relay 2>&1 | tail -10
        return 1
    fi

    local url
    url="$(python3 - "$dir/relay/creds.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
print(f"vless://{c['uuid']}@5.5.77.20:{c['vless_port']}?security=reality&sni={c['sni']}"
      f"&pbk={c['public_key']}&sid={c['short_id']}&fp=chrome&flow=xtls-rprx-vision&type=tcp#smoke")
PY
)"

    # Та же заглушка, что и в надзоре за правилами: иначе снесённое правило
    # вернётся через 30 секунд, и проверять будет нечего.
    cat > "$dir/bin/iptables-restore" <<'STUB'
#!/bin/sh
if [ -e /tmp/nf-fail ]; then
    echo "сбой, заданный тестом" >&2
    exit 2
fi
exec /usr/sbin/iptables-restore "$@"
STUB
    chmod +x "$dir/bin/iptables-restore"

    docker run -d --name "$c" --network "$net" --ip 5.5.77.30 \
        --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun \
        --sysctl net.ipv4.ip_forward=1 -p "127.0.0.1:$CANARY_PANEL_PORT:8000" \
        -e LIVE_MANAGEMENT_ENABLED=true -e AUTO_APPLY_ON_START=true \
        -e AWG_AUTO_UPDATE_ENABLED=false -e DEFAULT_SERVER_ADDRESS=10.79.0.1/24 \
        -e DEFAULT_LISTEN_PORT=51997 -e PUBLIC_HOST=5.5.77.30 \
        -e CASCADE_PROBE_URL=http://5.5.77.10/generate_204 ${CANARY_PANEL_ENV:-} \
        -v "$dir/data:/opt/panel/data" -v "$dir/awg_config:/etc/amnezia/amneziawg" \
        "$PANEL_IMAGE" >/dev/null
    docker cp "$dir/bin/iptables-restore" "$c:/usr/local/bin/iptables-restore" >/dev/null
    docker network connect --ip 100.64.78.30 smoke-canary-lan "$c"

    if ! wait_for 60 test -s "$dir/data/INITIAL_ADMIN_PASSWORD.txt" \
        || ! wait_for 45 curl -kfsS -o /dev/null "https://127.0.0.1:$CANARY_PANEL_PORT/"; then
        fail "панель стенда не поднялась"
        docker logs "$c" 2>&1 | tail -20
        return 1
    fi

    local pw
    pw="$(grep -oE '[A-Za-z0-9_-]{12,}' "$dir/data/INITIAL_ADMIN_PASSWORD.txt" | head -1)"
    CANARY_TOKEN="$(curl -kfsS -X POST "https://127.0.0.1:$CANARY_PANEL_PORT/api/auth/login" \
        -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$pw\"}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"

    local body
    body="$(python3 -c 'import json,sys; print(json.dumps({"cascade_enabled": True, "cascade_vless_url": sys.argv[1]}))' "$url")"
    curl -kfsS -o /dev/null -X PUT "https://127.0.0.1:$CANARY_PANEL_PORT/api/server" \
        -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' -d "$body" \
        || { fail "панель не приняла ссылку на релей"; return 1; }
    curl -kfsS -o /dev/null -X POST "https://127.0.0.1:$CANARY_PANEL_PORT/api/server/apply" \
        -H "Authorization: Bearer $CANARY_TOKEN" || true

    if wait_for 30 canary_status_has '"running":true'; then
        pass "каскад до релея поднят"
    else
        fail "каскад стенда не поднялся"
        docker exec "$c" tail -8 /opt/panel/data/cascade.log 2>/dev/null || true
        return 1
    fi

    # Как в compose: из привилегий только NET_ADMIN.
    docker run -d --name smoke-canary --network smoke-canary-lan --ip 100.64.78.40 --init --no-healthcheck \
        --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun \
        -e CANARY_INTERVAL_SECONDS="$interval" -e CANARY_ENDPOINT_HOST=100.64.78.30 \
        -e CANARY_TRACE_URL=http://5.5.77.10/cdn-cgi/trace \
        -e CANARY_DOWNLOAD_URL=http://5.5.77.10/1mb -e CANARY_DNS_SERVER=5.5.77.10 ${CANARY_ARGS:-} \
        -v "$dir/data/canary:/canary" --entrypoint python "$PANEL_IMAGE" -m app.canary_probe >/dev/null

    if wait_for 90 canary_status_has '"canary_ok":true'; then
        pass "канарейка зелёная на рабочем стенде"
    else
        fail "канарейка не позеленела за 90 с"
        cat "$dir/data/canary/result.json"
        docker logs smoke-canary 2>&1 | tail -5
        return 1
    fi

    canary_status_has '"canary_exit_ip":"5.5.77.20"' \
        && pass "трафик канарейки выходит с адреса релея" \
        || fail "адрес выхода канарейки не адрес релея"

    local visible
    visible="$(curl -kfsS -H "Authorization: Bearer $CANARY_TOKEN" "https://127.0.0.1:$CANARY_PANEL_PORT/api/peers")"
    [ "$visible" = "[]" ] && pass "служебный пир не виден в списке клиентов" \
        || fail "служебный пир попал в список клиентов: $visible"

    curl -kfsS -H "Authorization: Bearer $CANARY_TOKEN" "https://127.0.0.1:$CANARY_PANEL_PORT/api/status/metrics" \
        | grep -q '^noisefloor_canary_ok 1$' \
        && pass "noisefloor_canary_ok 1 в метриках" || fail "нет noisefloor_canary_ok 1 в метриках"
}

test_canary() {
    echo
    echo "Канарейка  ($PANEL_IMAGE)"
    local dir="$WORKDIR/canary" c=smoke-canary-panel
    canary_stand canary 15 || return
    local diag='cat "$dir/data/canary/result.json"; docker logs smoke-canary 2>&1 | tail -5'

    # Настоящая база работающей панели: снимок обязан проходить проверку.
    local api="https://127.0.0.1:$CANARY_PANEL_PORT/api" backup
    curl -kfsS -o /dev/null -X POST -H "Authorization: Bearer $CANARY_TOKEN" "$api/backup" || true
    backup=$(curl -kfsS -H "Authorization: Bearer $CANARY_TOKEN" "$api/backup/status" || true)
    if [[ "$backup" == *'"last_error":null'* && "$backup" != *'"last_success_at":null'* ]]; then
        pass "снимок базы панели проходит integrity_check"
    else
        fail "бэкап панели: $backup"
    fi

    # --- снесённое правило TPROXY ---
    docker exec "$c" touch /tmp/nf-fail
    docker exec "$c" sh -c 'iptables-save -t mangle | grep -e "-j TPROXY" | sed "s/^-A /-D /" \
        | while read -r rule; do eval "iptables -t mangle $rule"; done'
    if wait_for 120 canary_status_has '"canary_ok":false'; then
        pass "без правила TPROXY канарейка покраснела не позже 2 мин"
    else
        fail "канарейка не заметила снесённое правило TPROXY"
        eval "$diag"
    fi
    canary_status_has '"canary_stage":"exit_ip"' \
        && pass "причина: трафик вышел не с адреса релея" \
        || { fail "канарейка упала не на адресе выхода"; eval "$diag"; }
    canary_status_has '"running":true' \
        && pass "xray при этом жив: состояния показаны раздельно" \
        || fail "xray упал, тест проверил не то"

    docker exec "$c" rm /tmp/nf-fail
    wait_for 120 canary_status_has '"canary_ok":true' \
        && pass "после возврата правила канарейка зелёная" \
        || { fail "канарейка не вернулась после возврата правила"; eval "$diag"; return; }

    # --- MTU 1280 и потеря фрагментов ---
    # Настоящая чёрная дыра: панель шлёт полными пакетами, без фрагментов и без
    # ICMP, а veth отбрасывает всё длиннее MTU приёмного конца. Фрагментация на
    # панели не подходит: получатель соберёт пакет раньше своих цепочек. Правило
    # -m length тоже: в ядре Docker Desktop загрузка xt_length вешает iptables.
    docker exec "$c" ip route get 100.64.78.40 | grep -q ' dev eth1 ' \
        || fail "стенд: канарейка не за eth1 панели"
    docker exec smoke-canary ip link set eth0 mtu 1280
    if wait_for 120 canary_status_has '"canary_ok":false'; then
        pass "при MTU 1280 без фрагментов канарейка покраснела не позже 2 мин"
    else
        fail "канарейка не заметила потерю крупных пакетов"
        eval "$diag"
    fi
    canary_status_has '"canary_stage":"download"' \
        && pass "причина: встало скачивание, а не рукопожатие" \
        || { fail "канарейка упала не на скачивании"; eval "$diag"; }

    docker exec smoke-canary ip link set eth0 mtu 1500
    wait_for 120 canary_status_has '"canary_ok":true' \
        && pass "после возврата MTU канарейка зелёная" \
        || { fail "канарейка не вернулась после возврата MTU"; eval "$diag"; }

    canary_cleanup
}

# ------------------------------------------- два релея и падение xray панели ---

api_put_server() {
    curl -kfsS -o /dev/null -X PUT "https://127.0.0.1:$CANARY_PANEL_PORT/api/server" \
        -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' -d "$1"
}

panel_xray_pid() {
    docker exec smoke-canary-panel python -c '
import os
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        cmd = open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        continue
    if cmd.startswith(b"/usr/local/bin/xray\0run"):
        print(pid)
        break
' 2>/dev/null
}

panel_xray_started() {
    local pid
    pid="$(panel_xray_pid)"
    [ -n "$pid" ] && [ "$pid" != "$1" ]
}

panel_has_tproxy() {
    docker exec smoke-canary-panel iptables-save -t mangle | grep -q -e '-j TPROXY'
}

panel_no_tproxy() {
    ! panel_has_tproxy
}

web_forget() {
    docker exec smoke-canary-web sh -c ': > /tmp/seen'
}

web_saw() {
    docker exec smoke-canary-web grep -qxF "$1" /tmp/seen
}

panel_config_falls_back_to() {
    docker exec smoke-canary-panel grep -q "\"fallbackTag\": \"$1\"" /opt/panel/data/cascade-xray-config.json
}

test_failover() {
    echo
    echo "Два релея  ($PANEL_IMAGE)"
    local dir="$WORKDIR/failover" c=smoke-canary-panel
    canary_stand failover 5 || return

    mkdir -p "$dir/relay2"
    docker run -d --name smoke-canary-relay2 --network smoke-canary-net --ip 5.5.77.21 \
        -e LABEL=smoke-canary2 -e APP_CODENAME=SmokeCanary2 -e PUBLIC_HOST=5.5.77.21 \
        -v "$dir/relay2:/data" "$RELAY_IMAGE" >/dev/null
    if ! wait_for 45 test -s "$dir/relay2/creds.json"; then
        fail "второй релей не поднялся"
        return
    fi
    local body
    body="$(python3 - "$dir/relay2/creds.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
print(json.dumps({"vless_url": f"vless://{c['uuid']}@5.5.77.21:{c['vless_port']}?security=reality&sni={c['sni']}"
      f"&pbk={c['public_key']}&sid={c['short_id']}&fp=chrome&flow=xtls-rprx-vision&type=tcp#smoke2"}))
PY
)"
    curl -kfsS -o /dev/null -X POST "https://127.0.0.1:$CANARY_PANEL_PORT/api/server/cascade/relays" \
        -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' -d "$body" \
        && pass "резервный релей добавлен" || { fail "панель не приняла резервный релей"; return; }

    docker exec "$c" python -c '
import json
config = json.load(open("/opt/panel/data/cascade-xray-config.json"))
assert [b["tag"] for b in config["routing"]["balancers"]] == ["relays", "relays-probe"]
' && pass "в конфиге xray балансировщик" || fail "в конфиге xray нет балансировщика"

    if ! wait_for 60 canary_status_has '"active":true' \
        || ! wait_for 60 canary_status_has '"canary_ok":true'; then
        fail "xray не выбрал живой релей"
        docker exec "$c" tail -8 /opt/panel/data/cascade-xray.log
        docker exec "$c" xray api bi -server=127.0.0.1:10086 relays
        curl -kfsS -H "Authorization: Bearer $CANARY_TOKEN" "https://127.0.0.1:$CANARY_PANEL_PORT/api/server/cascade/status"; echo
        return
    fi
    pass "xray выбрал живой релей, канарейка зелёная"

    # Останавливаем тот, через который идёт трафик сейчас: иначе проверять нечего.
    local exit_ip standby t0
    exit_ip="$(canary_field canary_exit_ip)"
    case "$exit_ip" in
        5.5.77.20) standby=5.5.77.21; docker stop -t 0 smoke-canary-relay >/dev/null ;;
        5.5.77.21) standby=5.5.77.20; docker stop -t 0 smoke-canary-relay2 >/dev/null ;;
        *) fail "адрес выхода не адрес релея: $exit_ip"; return ;;
    esac
    t0="$(date +%s)"
    if wait_for 30 canary_exits_via "$standby"; then
        pass "канарейка восстановилась через второй релей за $(( $(date +%s) - t0 )) с"
    else
        fail "за 30 с канарейка не перешла на второй релей"
        canary_field canary_exit_ip; canary_field canary_error
        cat "$dir/data/canary/result.json"
        docker exec "$c" xray api bi -server=127.0.0.1:10086 relays
    fi

    # --- смерть xray панели ---
    local pid
    pid="$(panel_xray_pid)"
    docker exec "$c" kill -9 "$pid"
    t0="$(date +%s)"
    if wait_for 10 panel_xray_started "$pid"; then
        pass "xray панели перезапущен за $(( $(date +%s) - t0 )) с"
    else
        fail "xray панели не перезапущен за 10 с"
    fi

    # --- block: xray не поднимается, перехват на месте ---
    docker exec "$c" mv /usr/local/bin/xray /usr/local/bin/xray.off
    docker exec "$c" kill -9 "$(panel_xray_pid_any)"
    wait_for 10 canary_status_has '"running":false' || fail "стенд: xray не остановился"
    panel_has_tproxy && pass "block: без xray перехват остаётся" || fail "block: перехват снят"

    # --- direct: перехват снимается и возвращается ---
    api_put_server '{"cascade_all_down":"direct"}' || fail "панель не приняла direct"
    wait_for 15 panel_no_tproxy && pass "direct: без xray перехват снят" || fail "direct: перехват остался"
    web_forget
    wait_for 30 web_saw 5.5.77.30 \
        && pass "direct: клиенты выходят с адреса панели" \
        || fail "direct: клиенты не вышли с адреса панели"
    canary_status_has '"intercept_suspended":true' \
        && pass "панель показывает снятый перехват" || fail "панель не показывает снятый перехват"

    docker exec "$c" mv /usr/local/bin/xray.off /usr/local/bin/xray
    wait_for 70 canary_status_has '"running":true' || fail "xray не вернулся"
    wait_for 15 panel_has_tproxy && pass "xray вернулся, перехват на месте" || fail "перехват не вернулся"
    wait_for 30 canary_exits_via "$standby" \
        && pass "клиенты снова идут через релей" \
        || fail "клиенты не вернулись на релей"

    # --- direct, релеи мертвы, xray жив ---
    case "$standby" in
        5.5.77.20) docker stop -t 0 smoke-canary-relay >/dev/null ;;
        5.5.77.21) docker stop -t 0 smoke-canary-relay2 >/dev/null ;;
    esac
    web_forget
    wait_for 40 web_saw 5.5.77.30 \
        && pass "direct: все релеи мертвы, выход с адреса панели" \
        || fail "direct: при мёртвых релеях нет выхода"

    # --- block, релеи мертвы, xray жив: наружу ни байта ---
    api_put_server '{"cascade_all_down":"block"}' || fail "панель не приняла block"
    # Прежний процесс xray ещё мог выпустить запрос: забываем адреса после смены.
    wait_for 15 panel_config_falls_back_to cascade-out || fail "стенд: конфиг не сменился"
    wait_for 15 canary_status_has '"running":true' || fail "стенд: xray не вернулся"
    sleep_seconds 3
    web_forget
    sleep_seconds 15
    web_saw 5.5.77.30 \
        && fail "block: трафик вышел с адреса панели" \
        || pass "block: все релеи мертвы, с адреса панели никто не вышел"

    docker rm -f smoke-canary-relay2 >/dev/null 2>&1 || true
    canary_cleanup
}

# ---------------------------------------- самопроверка релея и откат агента ----

relay_api() {
    # Вход формой, как у администратора: у стендового релея нет проброшенного порта.
    docker exec smoke-canary-relay sh -c '
        [ -s /tmp/jar ] || curl -kfsS -o /dev/null -c /tmp/jar --data-urlencode username=admin \
            --data-urlencode password=smoke-relay-pass https://127.0.0.1:8001/login
        curl -kfsS -b /tmp/jar "$@"' sh "$@"
}

relay_xray_pid() {
    docker exec smoke-canary-relay python -c '
import os
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        cmd = open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        continue
    if cmd.startswith(b"/usr/local/bin/xray\0run") and b"xray-config.json" in cmd:
        print(pid)
        break
' 2>/dev/null
}

relay_router_reaches() {
    # Сертификат отдаёт сам хост: значит, nginx выбрал его по SNI.
    docker exec smoke-canary-relay sh -c "openssl s_client -connect 127.0.0.1:18443 -servername $1 \
        </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null" | grep -qF "$1"
}

relay_xray_replaced() {
    local now
    now="$(relay_xray_pid)"
    [ -n "$now" ] && [ "$now" != "$1" ]
}

panel_reaches_web() {
    [ "$(docker exec smoke-canary-panel curl -sS --max-time 5 \
        --socks5-hostname 127.0.0.1:10087 http://5.5.77.10/ip 2>/dev/null)" = "ip=5.5.77.20" ]
}

relay_uses_router() {
    docker exec smoke-canary-relay grep -q '"dest": "127.0.0.1:18443"' /data/xray-config.json
}

panel_sni() {
    docker exec smoke-canary-panel python -c '
import json
config = json.load(open("/opt/panel/data/cascade-xray-config.json"))
print(config["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"])'
}

relay_sni() {
    docker exec smoke-canary-relay python -c 'import json; print(json.load(open("/data/creds.json"))["sni"])'
}

panel_follows_relay() {
    [ "$(panel_sni)" = "$(relay_sni)" ]
}

panel_sync() {
    curl -kfsS -o /dev/null -X POST "https://127.0.0.1:$CANARY_PANEL_PORT/api/server/cascade/sync" \
        -H "Authorization: Bearer $CANARY_TOKEN"
}

cascade_downlink() {
    docker exec smoke-canary-panel xray api stats -server=127.0.0.1:10086 \
        -name 'outbound>>>cascade-out>>>traffic>>>downlink' 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["stat"].get("value", 0))' 2>/dev/null \
        || echo 0
}

# Смена SNI не рвёт идущую загрузку: принудительная ротация посреди неё.
test_rotation() {
    local seconds="${1:-60}" dir="$WORKDIR/rotation" c=smoke-canary-panel
    echo
    echo "Ротация SNI без обрывов, загрузка $seconds с  ($PANEL_IMAGE)"
    canary_stand rotation 30 || return

    # Включение ротации меняет конфиг: это единственный разрешённый перезапуск.
    local started
    started="$(relay_xray_pid)"
    relay_api -o /dev/null --data-urlencode enabled=on --data-urlencode interval_hours=24 \
        --data-urlencode 'pool=dl.google.com
www.amd.com
www.dell.com
www.asus.com' https://127.0.0.1:8001/api/rotation \
        || { fail "релей не принял пул"; return; }
    wait_for 15 relay_uses_router && wait_for 30 relay_xray_replaced "$started" \
        && pass "релей ведёт REALITY через маршрутизатор" \
        || { fail "маршрутизатор не включился"; docker logs smoke-canary-relay 2>&1 | tail -8; return; }
    relay_router_reaches www.amd.com \
        && pass "маршрутизатор довёл до хоста из пула" || fail "маршрутизатор не довёл до хоста из пула"

    local body
    body="$(python3 - "$dir/relay/creds.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
print(json.dumps({"cascade_sync_url": "https://5.5.77.20:8001", "cascade_sync_token": c["sync_token"]}))
PY
)"
    api_put_server "$body" || { fail "панель не приняла синхронизацию"; return; }
    panel_sync || fail "синхронизация с релеем не прошла"
    wait_for 40 panel_reaches_web || fail "стенд: каскад не вернулся после включения"

    local panel_pid relay_pid first second bytes got
    panel_pid="$(panel_xray_pid)"
    relay_pid="$(relay_xray_pid)"
    [ -n "$panel_pid" ] && [ -n "$relay_pid" ] || { fail "стенд: нет PID xray"; return; }

    docker exec -d "$c" sh -c "curl -sS -o /tmp/slow --stderr /tmp/slow.err --max-time $(( seconds + 30 )) \
        --socks5-hostname 127.0.0.1:10087 http://5.5.77.10/slow/$seconds; echo \$? > /tmp/slow.exit"
    sleep_seconds 5

    # Запросы всё время смены: ни один не должен выйти мимо релея.
    web_forget
    docker exec -d "$c" sh -c 'for i in $(seq 1 150); do
        curl -s -o /dev/null --max-time 2 --socks5-hostname 127.0.0.1:10087 http://5.5.77.10/hammer & sleep 0.1
    done'

    first="$(relay_sni)"
    relay_api -o /dev/null -X POST https://127.0.0.1:8001/api/rotation/now || fail "ротация не запустилась"
    second="$(relay_sni)"
    [ "$first" != "$second" ] && pass "релей сменил SNI: $first -> $second" || fail "SNI не сменился"
    panel_sync || fail "синхронизация после ротации не прошла"
    wait_for 15 panel_follows_relay && pass "панель перешла на новый SNI" \
        || fail "панель осталась на $(panel_sni), релей на $(relay_sni)"

    if [ "$(relay_xray_pid)" = "$relay_pid" ]; then
        pass "xray релея не перезапускался"
    else
        fail "xray релея перезапущен: $relay_pid -> $(relay_xray_pid)"
        relay_api https://127.0.0.1:8001/api/status | head -c 600; echo
        docker logs smoke-canary-relay 2>&1 | tail -25
    fi
    [ "$(panel_xray_pid)" = "$panel_pid" ] && pass "xray панели не перезапускался" || fail "xray панели перезапущен"

    local before after
    before="$(cascade_downlink)"
    got="$(docker exec "$c" curl -sS --max-time 10 --socks5-hostname 127.0.0.1:10087 http://5.5.77.10/ip)"
    [ "$got" = "ip=5.5.77.20" ] && pass "новое соединение идёт через релей с новым SNI" \
        || fail "новое соединение после смены: $got"
    docker exec "$c" curl -sS -o /dev/null --max-time 10 --socks5-hostname 127.0.0.1:10087 http://5.5.77.10/1mb
    after="$(cascade_downlink)"
    [ "$after" -gt "$before" ] && pass "счётчики исходящего считают после замены: $before -> $after" \
        || fail "счётчики исходящего встали после замены: $before -> $after"

    sleep_seconds 18
    web_saw 5.5.77.30 && fail "во время смены запрос вышел мимо релея" \
        || pass "во время смены ни один запрос не вышел мимо релея"
    web_saw 5.5.77.20 && pass "запросы шли через релей" || fail "контроль: журнал web пуст"

    wait_for $(( seconds + 30 )) docker exec "$c" test -s /tmp/slow.exit || fail "загрузка не закончилась"
    got="$(docker exec "$c" cat /tmp/slow.exit)"
    bytes="$(docker exec "$c" stat -c %s /tmp/slow)"
    if [ "$got" = 0 ] && [ "$bytes" = "$(( seconds * 10240 ))" ]; then
        pass "загрузка на $seconds с пережила ротацию: $bytes байт"
    else
        fail "загрузка оборвалась: код $got, байт $bytes из $(( seconds * 10240 ))"
        docker exec "$c" cat /tmp/slow.err
        docker exec "$c" tail -15 /opt/panel/data/cascade-xray.log
    fi

    started="$(relay_xray_pid)"
    relay_api -o /dev/null --data-urlencode enabled=on --data-urlencode extra=geohide.example \
        https://127.0.0.1:8001/api/geohide || fail "релей не принял GeoHide"
    wait_for 30 relay_xray_replaced "$started" || fail "стенд: включение GeoHide не применилось"
    relay_pid="$(relay_xray_pid)"
    relay_api -o /dev/null -X POST https://127.0.0.1:8001/api/geohide/refresh || fail "обновление GeoHide не прошло"
    relay_api -o /dev/null -X POST https://127.0.0.1:8001/api/geohide/refresh || fail "обновление GeoHide не прошло"
    # Дольше отложенного перезапуска.
    sleep_seconds 20
    [ "$(relay_xray_pid)" = "$relay_pid" ] \
        && pass "повторный geohide_apply не перезапускает xray" || fail "geohide_apply перезапустил xray"

    # Упавший маршрутизатор поднимает сторож, иначе не пройдёт ни одно рукопожатие.
    docker exec smoke-canary-relay python -c '
import os, signal
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        cmd = open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        continue
    if cmd.startswith(b"nginx: master"):
        os.kill(int(pid), signal.SIGKILL)
'
    sleep_seconds 1
    wait_for 15 relay_router_reaches www.amd.com && pass "упавший маршрутизатор поднят" \
        || fail "маршрутизатор не поднялся"

    canary_cleanup
}

# Сколько фрагментов порта AWG прошло через eth0 панели за $1 секунд.
count_fragments() {
    docker exec smoke-canary-panel python -c '
import socket, struct, sys, time
# ETH_P_ALL: сокет на ETH_P_IP не видит исходящие пакеты, а фрагменты идут наружу.
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 24)
sock.settimeout(1)
end, frags, seen = time.time() + int(sys.argv[1]), 0, 0
biggest = (0, "", "")
while time.time() < end:
    try:
        data, addr = sock.recvfrom(65535)
    except socket.timeout:
        continue
    if not addr[0].startswith("eth") or addr[1] != 0x0800 or len(data) < 34 or data[23] != 17:
        continue
    seen += 1
    flags = struct.unpack("!H", data[20:22])[0]
    frags += bool(flags & 0x3fff)
    if len(data) - 14 > biggest[0]:
        biggest = (len(data) - 14, addr[0], hex(flags))
print(frags, seen, *biggest)
' "$1"
}

test_mtu() {
    echo
    echo "MTU из профиля  ($PANEL_IMAGE)"
    canary_stand mtu 5 || return
    local frags

    # Контроль: тот же стенд при MTU 1420 обязан дать фрагменты, иначе счётчик слеп.
    api_put_server '{"s4":32,"mtu":1420}' || { fail "панель не приняла профиль"; return; }
    sleep_seconds 20
    wait_for 60 canary_status_has '"canary_ok":true' || fail "стенд: канарейка не вернулась при MTU 1420"
    frags="$(count_fragments 70)"
    [ "${frags%% *}" -gt 0 ] && pass "контроль: при S4 32 и MTU 1420 есть фрагменты ($frags)" \
        || fail "контроль: фрагментов нет даже при MTU 1420 ($frags)"

    api_put_server '{"mtu":null}' || { fail "панель не сбросила MTU"; return; }
    sleep_seconds 20
    wait_for 60 canary_status_has '"canary_ok":true' || fail "стенд: канарейка не вернулась при расчётном MTU"
    docker exec smoke-canary-panel cat /sys/class/net/awg0/mtu | grep -qx 1392 \
        && pass "на интерфейсе расчётный MTU 1392" || fail "на интерфейсе не 1392"
    frags="$(count_fragments 70)"
    [ "${frags%% *}" = 0 ] && pass "при расчётном MTU фрагментов нет ($frags)" \
        || fail "при расчётном MTU есть фрагменты ($frags)"
    canary_cleanup
}

# Что видит сайт, когда клиент ходит через настоящий туннель.
tunnel_get() {
    # Отказ curl здесь результат проверки, set -e не должен оборвать прогон.
    docker exec smoke-canary curl -sS --max-time 10 "$@" 2>&1 || true
}

split_checks() {
    local c=smoke-canary-panel label="$1" got
    # Российский адрес на стенде и подмена: DNS хоста отвечает им на чужой домен.
    docker network create --subnet 77.88.8.0/24 smoke-canary-ru >/dev/null
    docker network connect --ip 77.88.8.8 smoke-canary-ru smoke-canary-web
    docker network connect --ip 77.88.8.30 smoke-canary-ru "$c"
    docker exec "$c" sh -c 'echo "77.88.8.8 blocked.example" >> /etc/hosts'
    # Релей резолвит имя сам: у него ответ настоящий.
    docker exec smoke-canary-relay sh -c 'echo "5.5.77.10 blocked.example" >> /etc/hosts'

    api_put_server '{"split_ru_direct":true,"dns":"5.5.77.10"}' || { fail "$label: панель не включила разделение"; return; }
    sleep_seconds 3
    wait_for 40 canary_status_has '"canary_ok":true' || fail "$label: канарейка не вернулась после включения"

    got="$(tunnel_get http://77.88.8.8/ip)"
    [ "$got" = "ip=77.88.8.30" ] && pass "$label: российский адрес идёт напрямую" \
        || fail "$label: российский адрес: $got"
    got="$(tunnel_get --resolve blocked.example:80:5.5.77.10 http://blocked.example/ip)"
    [ "$got" = "ip=5.5.77.20" ] && pass "$label: домен с подменой на хосте идёт через каскад" \
        || fail "$label: домен с подменой на хосте: $got"
    got="$(tunnel_get http://5.5.77.10/ip)"
    [ "$got" = "ip=5.5.77.20" ] && pass "$label: остальное идёт через каскад" || fail "$label: остальное: $got"
}

test_split() {
    echo
    echo "Разделение РФ/не-РФ  ($PANEL_IMAGE)"
    canary_stand split 5 || return
    split_checks tproxy
    canary_cleanup

    # dns.server панели - web стенда: канарейка спрашивает его через слушатель.
    CANARY_PANEL_ENV="-e CASCADE_INTERCEPT_MODE=redirect -e CASCADE_DNS_VIA_CASCADE=true"
    canary_stand split-redirect 5 || { CANARY_PANEL_ENV=; return; }
    CANARY_PANEL_ENV=
    split_checks redirect
    canary_cleanup
}

# Сколько новых TCP-соединений открыла панель к релею 5.5.77.20 за время $1 секунд.
count_relay_syns() {
    docker exec smoke-canary-panel python -c '
import socket, sys, time
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 24)
sock.settimeout(1)
end, syns = time.time() + int(sys.argv[1]), 0
relay = bytes([5, 5, 77, 20])
while time.time() < end:
    try:
        data, addr = sock.recvfrom(128)
    except socket.timeout:
        continue
    if addr[4:] and addr[2] != 4:
        continue
    if data[12:14] != b"\x08\x00" or data[23] != 6 or data[30:34] != relay:
        continue
    ihl = (data[14] & 15) * 4
    syns += data[14 + ihl + 13] & 0x12 == 0x02
print(syns)
' "$1"
}

# Клиент за туннелем: 100 запросов с новых портов. Печатает число ответов.
dns_burst() {
    docker exec smoke-canary python -c '
import socket, struct, sys
ok = 0
for i in range(100):
    name = b"\x03n%02d\x07example\x00" % i
    query = struct.pack("!HHHHHH", i + 1, 0x0100, 1, 0, 0, 0) + name + b"\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        for _ in range(2):
            try:
                sock.sendto(query, ("5.5.77.10", 53))
                ok += sock.recv(1500)[:2] == query[:2]
                break
            except OSError:
                continue
print(ok)
'
}

# Один запрос типа $2 про имя $1: печатает число ответов.
dns_ask() {
    docker exec smoke-canary python -c '
import socket, struct, sys
name = b"".join(bytes([len(p)]) + p.encode() for p in sys.argv[1].split(".")) + b"\x00"
query = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", int(sys.argv[2]), 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(4)
sock.sendto(query, ("5.5.77.10", 53))
print(struct.unpack("!H", sock.recv(1500)[6:8])[0])
' "$1" "$2" 2>&1 | tail -1
}

# Отправка UDP на порт $1 из-за туннеля: адрес, каким его увидел web, или "тишина".
udp_exit() {
    docker exec smoke-canary python -c '
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(b"x" * 200, ("5.5.77.10", int(sys.argv[1])))
try:
    print(sock.recv(1500).decode())
except OSError:
    print("тишина")
' "$1"
}

test_xudp_stand() {
    local label="$1" want="$2" syns answers
    api_put_server '{"dns":"5.5.77.10"}' || { fail "$label: панель не приняла DNS"; return; }
    sleep_seconds 3
    wait_for 60 canary_status_has '"canary_ok":true' || fail "$label: канарейка не вернулась"
    count_relay_syns 30 > "$WORKDIR/syns" &
    local counter=$!
    sleep_seconds 2
    answers="$(dns_burst)"
    wait "$counter"
    syns="$(cat "$WORKDIR/syns")"
    [ "$answers" = 100 ] && pass "$label: на 100 запросов 100 ответов" || fail "$label: ответов $answers из 100"
    if [ "$syns" -le "$want" ] && [ "$label" != "без XUDP" ]; then
        pass "$label: соединений к релею за 100 запросов: $syns"
    elif [ "$label" = "без XUDP" ] && [ "$syns" -ge "$want" ]; then
        pass "контроль: без XUDP соединений к релею $syns"
    else
        fail "$label: соединений к релею $syns, порог $want"
    fi
}

test_xudp() {
    echo
    echo "UDP и DNS через каскад  ($PANEL_IMAGE)"
    canary_stand xudp-off 60 || return
    test_xudp_stand "без XUDP" 80
    canary_cleanup

    CANARY_PANEL_ENV="-e CASCADE_XUDP=true"
    canary_stand xudp 60 || { CANARY_PANEL_ENV=; return; }
    CANARY_PANEL_ENV=
    test_xudp_stand "с XUDP" 9

    local got cached
    [ "$(dns_ask cached.example 1)" = 1 ] || fail "запрос A без ответа"
    [ "$(dns_ask cached.example 1)" = 1 ] || fail "повторный запрос A без ответа"
    cached="$(docker exec smoke-canary-web sh -c "grep -c '^1 .*636163686564' /tmp/dns-seen" || true)"
    [ "$cached" = 1 ] && pass "повторный запрос ответил кэш" || fail "до резолвера дошло запросов: $cached"
    got="$(dns_ask txt.example 16)"
    [ "$got" = 1 ] && pass "запрос TXT проходит" || fail "запрос TXT: $got"
    got="$(udp_exit 3478)"
    [ "$got" = 5.5.77.20 ] && pass "UDP выходит с адреса релея" || fail "UDP: $got"
    got="$(udp_exit 443)"
    [ "$got" = "тишина" ] && pass "QUIC отклонён" || fail "UDP/443: $got"
    canary_cleanup
}

# Подключение с клиента к адресу IPv6: "<секунды> <исход>".
v6_try() {
    docker exec smoke-canary python -c '
import socket, sys, time
proto = sys.argv[1]
sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
sock.settimeout(4)
start = time.time()
try:
    sock.connect((sys.argv[2], 443))
    if proto == "udp":
        sock.send(b"x")
        sock.recv(1)
    result = "ok"
except OSError as error:
    result = type(error).__name__
print(round(time.time() - start, 2), result)
' "$1" "$2"
}

v6_refused() {
    local got
    got="$(v6_try tcp 2001:db8::1)"
    [ "${got#* }" = ConnectionRefusedError ]
}

test_ipv6() {
    echo
    echo "IPv6 клиентов  ($PANEL_IMAGE)"
    local v6="--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0"
    local got ula c=smoke-canary-panel
    CANARY_PANEL_ENV="$v6"
    CANARY_ARGS="$v6"
    canary_stand ipv6 5 || { CANARY_PANEL_ENV=; CANARY_ARGS=; return; }
    CANARY_PANEL_ENV=
    CANARY_ARGS=

    [ "$(docker exec "$c" cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0 ] \
        && pass "глобальная пересылка IPv6 выключена" || fail "включена пересылка IPv6"
    docker exec "$c" awg show awg0 allowed-ips | grep -q 'fd[0-9a-f:]*/128' \
        && pass "у пира есть адрес ULA" || fail "у пира нет адреса ULA"

    ula="$(docker exec smoke-canary python -c '
import json, re
print(re.search(r"fd[0-9a-f:]+/128", json.load(open("/canary/config.json"))["conf"]).group())')"
    # Служебный пир идёт только по IPv4, обычный клиент получает и ::/0.
    docker exec smoke-canary sh -c 'awg set canary0 peer "$(awg show canary0 peers)" allowed-ips 0.0.0.0/0,::/0'
    docker exec smoke-canary ip -6 address add "$ula" dev canary0
    docker exec smoke-canary ip -6 route add ::/0 dev canary0

    # Отказ обязан дойти до клиента через туннель: иначе это не быстрый откат.
    got="$(v6_try tcp 2001:db8::1)"
    [ "${got#* }" = ConnectionRefusedError ] && [ "${got%%.*}" = 0 ] \
        && pass "TCP по IPv6: сразу отказ ($got)" || fail "TCP по IPv6: $got"
    got="$(v6_try udp 2001:db8::1)"
    [ "${got#* }" = PermissionError ] && [ "${got%%.*}" -lt 2 ] \
        && pass "UDP по IPv6: отказ без таймаута ($got)" || fail "UDP по IPv6: $got"

    docker exec smoke-canary sh -c 'printf "5.5.77.10 dual.example\n2001:db8::10 dual.example\n" >> /etc/hosts'
    docker exec smoke-canary-relay sh -c 'echo "5.5.77.10 dual.example" >> /etc/hosts'
    got="$(docker exec smoke-canary curl -sS -m 5 -o /dev/null -w '%{http_code} %{time_total}' http://dual.example/ 2>&1 || true)"
    [ "${got%% *}" = 200 ] && [ "${got#* }" \< 1 ] \
        && pass "сайт с A и AAAA открывается без задержки ($got)" || fail "dual-stack: $got"

    # Контроль: RST даёт именно наше правило. Без него отвечает маршрутизация
    # панели, у стенда нет маршрута IPv6.
    docker exec "$c" ip -6 rule del iif awg0 lookup 20231
    got="$(v6_try tcp 2001:db8::1)"
    [ "${got#* }" != ConnectionRefusedError ] && pass "контроль: без правила нет RST ($got)" \
        || fail "контроль: RST и без правила"
    wait_for 60 v6_refused && pass "надзор вернул снятое правило IPv6" \
        || fail "надзор не вернул правило IPv6"

    # Выключение настройки снимает всё, что ставили.
    docker exec "$c" noisefloor-rules up --iface awg0 --egress eth0 --mode off >/dev/null
    if docker exec "$c" sh -c 'ip6tables -S | grep -q NOISEFLOOR-V6 || ip -6 rule list | grep -q 20231'; then
        fail "без флага остались правила IPv6"
    else
        pass "без флага правила IPv6 сняты"
    fi
    canary_cleanup
}

selfcheck_cleanup() {
    docker rm -f smoke-selfcheck smoke-agent-relay-1 >/dev/null 2>&1 || true
    docker image rm -f nf-smoke-agent-relay:broken nf-smoke-agent-relay:current \
        nf-smoke-agent-relay:previous nf-smoke-agent-relay:stable >/dev/null 2>&1 || true
}

selfcheck_health() {
    docker exec smoke-selfcheck sh -c 'curl -ksS "https://127.0.0.1:${PANEL_PORT}/api/health"' 2>/dev/null
}

selfcheck_health_has() {
    [[ "$(selfcheck_health)" == *$1* ]]
}

agent_relay_healthy() {
    [ "$(docker inspect smoke-agent-relay-1 --format '{{.State.Health.Status}}' 2>/dev/null)" = healthy ]
}

# Заменяет закрытый ключ в конфиге на чужой: xray запускается, клиенты не проходят.
BREAK_REALITY_PY='
import json, os, re, signal, subprocess
out = subprocess.run(["xray", "x25519"], capture_output=True, text=True).stdout
key = re.search(r"Private\s*[Kk]ey:\s*(\S+)", out).group(1)
path = "/data/xray-config.json"
config = json.load(open(path))
config["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] = key
json.dump(config, open(path, "w"))
# Сторож поднимет xray уже с испорченным конфигом.
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        cmd = open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        continue
    if cmd.startswith(b"/usr/local/bin/xray") and b"xray-config.json" in cmd:
        os.kill(int(pid), signal.SIGTERM)
'

test_selfcheck() {
    echo
    echo "Самопроверка релея  ($RELAY_IMAGE)"
    local dir="$WORKDIR/selfcheck" c=smoke-selfcheck
    mkdir -p "$dir/data" "$dir/agent/data"
    selfcheck_cleanup
    trap 'selfcheck_cleanup; canary_cleanup; docker rm -f smoke-rules-panel >/dev/null 2>&1 || true; cleanup' EXIT

    docker run -d --name "$c" -e LABEL=smoke -e APP_CODENAME=Smoke -e PUBLIC_HOST=127.0.0.1 \
        -e SELFCHECK_INTERVAL_SECONDS=10 -e SELFCHECK_RETRY_SECONDS=5 \
        -v "$dir/data:/data" "$RELAY_IMAGE" >/dev/null

    if wait_for 60 selfcheck_health_has '"selfcheck":"ok"'; then
        pass "самопроверка прошла через настоящий REALITY"
    else
        fail "самопроверка не дошла до ok: $(selfcheck_health)"
        docker logs "$c" 2>&1 | tail -10
        return
    fi

    docker exec -i "$c" python3 -c "$BREAK_REALITY_PY"
    if wait_for 60 selfcheck_health_has '"selfcheck":"failed"'; then
        pass "сломанный realitySettings: /api/health отвечает 503"
    else
        fail "/api/health не заметил сломанный REALITY: $(selfcheck_health)"
    fi
    selfcheck_health | grep -q '"xray_running":true' \
        && pass "процесс xray при этом жив: раньше такой релей считался здоровым" \
        || fail "xray не запущен, тест проверил не то"
    docker rm -f "$c" >/dev/null

    # --- агент: настоящие контейнеры и compose, подменён только docker pull ---
    local d="$dir/agent" repo=nf-smoke-agent-relay broken="$dir/broken"
    mkdir -p "$broken"
    docker tag "$RELAY_IMAGE" "$repo:current"
    cat > "$broken/Dockerfile" <<EOF
FROM $RELAY_IMAGE
RUN sed -i 's/"privateKey": creds\["private_key"\]/"privateKey": "cGxlYXNlLWJyZWFrLXJlYWxpdHktZm9yLXNtb2tlLTA"/' /app/app.py
EOF
    if ! docker build -q -t "$repo:broken" "$broken" >/dev/null; then
        fail "сломанный образ не собрался"
        return
    fi
    if [ "$(docker run --rm --entrypoint grep "$repo:broken" -c 'cGxlYXNlLWJyZWFrLXJlYWxpdHktZm9yLXNtb2tlLTA' /app/app.py)" = 0 ]; then
        fail "стенд: правка не попала в образ"
        return
    fi
    docker tag "$repo:broken" "$repo:stable"

    cat > "$d/docker-compose.yml" <<EOF
name: smoke-agent
services:
  relay:
    image: $repo:current
    container_name: smoke-agent-relay-1
    environment:
      LABEL: smoke
      APP_CODENAME: Smoke
      PUBLIC_HOST: 127.0.0.1
      SELFCHECK_RETRY_SECONDS: 5
    volumes:
      - ./data:/data
EOF
    (cd "$d" && docker compose up -d >/dev/null 2>&1)
    if ! wait_for 90 agent_relay_healthy; then
        fail "исходный релей не стал healthy"
        return
    fi
    pass "исходная версия здорова"

    local before
    before="$(docker inspect smoke-agent-relay-1 --format '{{.Image}}')"
    printf 'relay=%s\n' "$d" > "$dir/services"
    # Функция, а не файл в PATH: /tmp бывает смонтирован с noexec.
    local rc=0
    (
        docker() {
            [ "$1" = pull ] && return 0
            command docker "$@"
        }
        export -f docker
        NOISEFLOOR_SERVICES_FILE="$dir/services" \
            bash "$(cd "$(dirname "$0")/.." && pwd)/tools/noisefloor" update relay
    ) >"$dir/agent.log" 2>&1 || rc=$?

    grep -q 'новая версия не поднялась' "$dir/agent.log" \
        && pass "агент поставил новую версию и не дождался здоровья" \
        || { fail "агент не дошёл до проверки здоровья"; tail -5 "$dir/agent.log"; return; }
    [ "$rc" != 0 ] && pass "агент сообщил, что обновление не удалось" \
        || { fail "агент посчитал сломанный релиз удачным"; tail -5 "$dir/agent.log"; }
    [ "$(docker inspect smoke-agent-relay-1 --format '{{.Image}}')" = "$before" ] \
        && pass "агент вернул прежний образ" \
        || { fail "после обновления работает не прежний образ"; tail -5 "$dir/agent.log"; }
    grep -q '"rolled_back": true' "$d/data/update-result.json" \
        && pass "откат записан в update-result.json" \
        || fail "нет записи об откате: $(cat "$d/data/update-result.json" 2>/dev/null)"

    (cd "$d" && docker compose down >/dev/null 2>&1) || true
    selfcheck_cleanup
}

# ------------------------------------------------------------ уведомления ----

hook_log() {
    docker exec smoke-canary-web sh -c 'cat /tmp/hook 2>/dev/null' || true
}

hook_has() {
    [[ "$(hook_log)" == *$1* ]]
}

test_notify() {
    echo
    echo "Уведомления"
    CANARY_PANEL_ENV="-e NOTIFY_INTERVAL_SECONDS=2 -e NOTIFY_HOLD_SECONDS=4 -e NOTIFY_MIN_INTERVAL_SECONDS=4 -e NOTIFY_TELEGRAM_API=http://5.5.77.10"
    CANARY_RELAY_ENV="-e NOTIFY_WEBHOOK_URL=http://5.5.77.10/relay -e NOTIFY_PANEL_SILENT_MINUTES=0.1"
    canary_stand notify 5 || { CANARY_PANEL_ENV=; CANARY_RELAY_ENV=; return; }
    CANARY_PANEL_ENV=; CANARY_RELAY_ENV=
    local api="https://127.0.0.1:$CANARY_PANEL_PORT/api/notify" auth="Authorization: Bearer $CANARY_TOKEN"
    local json='Content-Type: application/json' dir="$WORKDIR/notify"

    curl -kfsS -o /dev/null -X PUT "$api" -H "$auth" -H "$json" \
        -d '{"webhook_url":"http://5.5.77.10/hook","telegram_chat_id":"42","telegram_token":"123:smoke"}' \
        || { fail "настройки уведомлений не сохранились"; return; }
    [ "$(stat -c %a "$dir/data/notify.json")" = 600 ] && pass "файл настроек с правами 600" \
        || fail "права notify.json: $(stat -c %a "$dir/data/notify.json")"
    curl -kfsS "$api" -H "$auth" | grep -q '123:smoke' && fail "токен бота отдаётся наружу" \
        || pass "токен бота в API не отдаётся"

    curl -kfsS -o /dev/null -X POST "$api/test" -H "$auth" || fail "тестовое сообщение не ушло"
    hook_has '5.5.77.20 /hook*тестовое' && pass "тестовое сообщение пришло через каскад, с адреса релея" \
        || fail "тестовое сообщение: $(hook_log)"
    hook_has '5.5.77.20 /bot123:smoke/sendMessage 42 *тестовое' && pass "Telegram: токен в адресе, чат в теле, через каскад" \
        || fail "тестовое сообщение в Telegram: $(hook_log)"

    # --- релей лёг: канарейка красная, отправка уходит напрямую ---
    docker stop smoke-canary-relay >/dev/null
    if wait_for 90 hook_has '5.5.77.30 /hook*канарейка упала'; then
        pass "канарейка упала: сообщение пришло, каскад лежит, ушло напрямую"
    else
        fail "нет сообщения о падении канарейки: $(hook_log)"
    fi
    local count
    sleep_seconds 10
    count="$(hook_log | grep -c ' /hook .*канарейка упала' || true)"
    [ "$count" = 1 ] && pass "о падении сообщено один раз" || fail "сообщений о падении: $count"

    docker start smoke-canary-relay >/dev/null
    if wait_for 90 hook_has 'канарейка восстановилась'; then
        pass "канарейка восстановилась: сообщение пришло"
    else
        fail "нет сообщения о восстановлении: $(hook_log)"
    fi

    # --- снесённые правила ---
    docker exec smoke-canary-panel sh -c 'iptables-save -t mangle | grep -e "-j TPROXY" | sed "s/^-A /-D /" \
        | while read -r rule; do eval "iptables -t mangle $rule"; done'
    if wait_for 60 hook_has 'правила фаервола снесли'; then
        pass "восстановление правил: сообщение пришло"
    else
        fail "нет сообщения о восстановлении правил: $(hook_log)"
    fi

    # --- панель перестала ходить на релей ---
    local sync_token
    sync_token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sync_token"])' "$dir/relay/creds.json")"
    docker exec smoke-canary-panel curl -kfsS -o /dev/null -H "Authorization: Bearer $sync_token" \
        "https://5.5.77.20:8001/api/sync" || fail "релей не ответил на синхронизацию"
    if wait_for 45 hook_has '5.5.77.20 /relay*панель не синхронизировалась'; then
        pass "релей сам сообщил о молчании панели"
    else
        fail "релей промолчал: $(hook_log)"
    fi
    docker exec smoke-canary-panel curl -kfsS -o /dev/null -H "Authorization: Bearer $sync_token" \
        "https://5.5.77.20:8001/api/sync" || true
    if wait_for 30 hook_has 'панель снова на связи'; then
        pass "релей сообщил о восстановлении связи"
    else
        fail "нет сообщения о возврате панели: $(hook_log)"
    fi
    canary_cleanup
}

# ------------------------------------------------------- запасной вход ----

fallback_get() {
    curl -kfsS "https://127.0.0.1:$CANARY_PANEL_PORT/api/fallback" -H "Authorization: Bearer $CANARY_TOKEN"
}

fallback_put() {
    curl -kfsS -o /dev/null -X PUT "https://127.0.0.1:$CANARY_PANEL_PORT/api/fallback" \
        -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' -d "$1"
}

fallback_has() {
    [[ "$(fallback_get 2>/dev/null || true)" == *$1* ]]
}

fallback_client_enabled() {
    curl -kfsS -o /dev/null -X PATCH "https://127.0.0.1:$CANARY_PANEL_PORT/api/fallback/clients/$1" \
        -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' -d "{\"enabled\":$2}" \
        || fail "клиент $1 не переключён"
}

fb_curl() {
    docker exec smoke-canary-fb curl -sS -o /dev/null --max-time 8 --proxy socks5h://127.0.0.1:1080 "$@"
}

test_fallback() {
    echo
    echo "Запасной вход VLESS"
    canary_stand fallback 5 || return
    local dir="$WORKDIR/fallback" sni relay_port settings link
    grep -q fallback-in "$dir/data/cascade-xray-config.json" \
        && fail "вход есть в конфиге без включения" || pass "по умолчанию входа в конфиге нет"
    fallback_has '"enabled":false' && pass "по умолчанию выключен" || fail "выключен ли: $(fallback_get)"

    sni="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sni"])' "$dir/relay/creds.json")"
    # Камуфляж стенда: сам релей. Снаружи он неотличим от сайта и в сеть выходить не надо.
    relay_port="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vless_port"])' "$dir/relay/creds.json")"
    settings="{\"enabled\":true,\"port\":18443,\"sni\":\"$sni\",\"dest\":\"5.5.77.20:$relay_port\"}"
    fallback_put "$settings" || { fail "настройки входа не сохранились"; return; }
    fallback_has '"listening":false' && pass "без клиентов порт закрыт" || fail "порт без клиентов: $(fallback_get)"
    if curl -ks -o /dev/null -w '%{http_code}' -X PUT "https://127.0.0.1:$CANARY_PANEL_PORT/api/fallback" \
        -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' \
        -d "{\"enabled\":true,\"port\":10087,\"sni\":\"$sni\",\"dest\":\"5.5.77.20:$relay_port\"}" | grep -q 422; then
        pass "порт самого xray не принимается"
    else
        fail "порт самого xray принят"
    fi

    link="$(curl -kfsS -X POST "https://127.0.0.1:$CANARY_PANEL_PORT/api/fallback/clients" \
        -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' -d '{"name":"смок"}' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["link"])')"
    if wait_for 20 fallback_has '"listening":true'; then
        pass "вход слушает порт после добавления клиента"
    else
        fail "вход не поднялся: $(fallback_get)"
        return
    fi

    [[ "$link" == vless://*@100.64.78.30:18443\?* ]] && pass "в ссылке адрес сервера и порт входа" \
        || fail "ссылка: ${link%%\?*}"

    # Настоящий клиент: всё берётся из выданной ссылки, кроме адреса. В стенде
    # адрес сервера внутренний, снаружи панель видна как 5.5.77.30.
    python3 - "$link" > "$dir/fb-client.json" <<'PY'
import json, sys
from urllib.parse import parse_qs, urlparse
u = urlparse(sys.argv[1])
q = {k: v[0] for k, v in parse_qs(u.query).items()}
print(json.dumps({
    "log": {"loglevel": "warning"},
    "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": {"auth": "noauth"}}],
    "outbounds": [{"protocol": "vless",
        "settings": {"vnext": [{"address": "5.5.77.30", "port": u.port,
            "users": [{"id": u.username, "encryption": "none", "flow": q["flow"]}]}]},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "serverName": q["sni"], "fingerprint": q["fp"], "publicKey": q["pbk"], "shortId": q["sid"]}}}],
}))
PY
    docker run -d --name smoke-canary-fb --network smoke-canary-net --ip 5.5.77.40 \
        -v "$dir/fb-client.json:/c.json:ro" --entrypoint xray "$PANEL_IMAGE" run -config /c.json >/dev/null
    sleep_seconds 2

    web_forget
    if fb_curl http://5.5.77.10/generate_204 && web_saw 5.5.77.20; then
        pass "клиент VLESS вышел в сеть с адреса релея"
    else
        fail "клиент VLESS не прошёл"
        docker logs smoke-canary-fb 2>&1 | tail -5
        return
    fi
    web_saw 5.5.77.30 && fail "трафик вышел с адреса панели" || pass "мимо релея трафик не ушёл"

    # Проверяется результат, а не правило панели nf-vless-private: на xray 26.7.28
    # запрос не доходит и без него (мутацией проверено), само правило держат unit-тесты.
    docker network create --subnet 10.77.0.0/24 smoke-canary-priv >/dev/null
    docker network connect --ip 10.77.0.10 smoke-canary-priv smoke-canary-web
    docker network connect --ip 10.77.0.20 smoke-canary-priv smoke-canary-relay
    web_forget
    docker exec smoke-canary-relay curl -sS -o /dev/null --max-time 5 http://10.77.0.10/generate_204 \
        || fail "контроль: релей не видит частную сеть"
    web_saw 10.77.0.20 && pass "контроль: частный адрес доступен с релея" || fail "контроль: запрос релея не дошёл"
    web_forget
    fb_curl http://10.77.0.10/generate_204 2>/dev/null || true
    web_saw 10.77.0.20 && fail "клиент дотянулся до частной сети релея" || pass "частная сеть релея закрыта"

    # --- занятый порт не должен стоить каскада ---
    docker exec -d smoke-canary-panel python -m http.server 18444 >/dev/null
    sleep_seconds 2
    fallback_put "${settings/18443/18444}" || fail "смена порта не сохранилась"
    if fallback_has 'порт 18444/tcp занят'; then
        pass "занятый порт: предупреждение, вход не поднят"
    else
        fail "занятый порт: $(fallback_get)"
    fi
    wait_for 15 canary_status_has '"running":true' && pass "каскад при занятом порте работает" \
        || fail "занятый порт уронил каскад"
    fallback_put "$settings" || fail "возврат порта не сохранился"

    # --- переживает перезапуск панели ---
    docker restart smoke-canary-panel >/dev/null
    if wait_for 60 fallback_has '"listening":true'; then
        pass "после перезапуска панели вход поднялся сам"
    else
        fail "после перезапуска входа нет: $(fallback_get)"
    fi
    sleep_seconds 2
    web_forget
    if wait_for 20 fb_curl http://5.5.77.10/generate_204 && web_saw 5.5.77.20; then
        pass "та же ссылка работает после перезапуска"
    else
        fail "ссылка перестала работать после перезапуска"
    fi

    # --- выключенный клиент не проходит, хотя порт открыт вторым клиентом ---
    curl -kfsS -o /dev/null -X POST "https://127.0.0.1:$CANARY_PANEL_PORT/api/fallback/clients" \
        -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' -d '{"name":"второй"}' \
        || fail "второй клиент не создан"
    fallback_client_enabled 1 false
    if wait_for 20 fallback_has '"listening":true' && ! fb_curl http://5.5.77.10/generate_204 2>/dev/null; then
        pass "выключенный клиент не проходит при открытом порте"
    else
        fail "выключенный клиент прошёл: $(fallback_get)"
    fi
    fallback_client_enabled 2 false
    fallback_has '"listening":false' && pass "без включённых клиентов порт закрыт" \
        || fail "порт после выключения клиентов: $(fallback_get)"
    fallback_put "${settings/true/false}" || fail "вход не выключился"
    grep -q fallback-in "$dir/data/cascade-xray-config.json" \
        && fail "вход остался в конфиге" || pass "выключение убирает вход из конфига"
    canary_cleanup
}

# ------------------------------------------- бот Telegram из установщика ----

test_install_telegram() {
    echo
    echo "Бот Telegram в install.sh"
    local script dir bin out
    local token=123456:ABC-def_1 root
    root="$(cd "$(dirname "$0")/.." && pwd)"
    for script in amneziawg-panel/install.sh vless-reality/install.sh; do
        dir="$(mktemp -d)"
        bin="$(mktemp -d "$HOME/nf-stub.XXXXXX")"  # /tmp бывает noexec
        # Docker подменён: проверяем файл и команду, сервер не нужен.
        printf '#!/bin/sh\necho "$@" >> "%s/calls"\n' "$dir" > "$bin/docker"
        chmod +x "$bin/docker"
        printf 'KEEP=1\nNOTIFY_TELEGRAM_TOKEN=9:old\nNOTIFY_TELEGRAM_CHAT_ID=1\nLAST=x\n' > "$dir/.env"

        out="$(NOTIFY_TELEGRAM_TOKEN=$token PATH="$bin:$PATH" bash "$root/$script" \
            --telegram-only --telegram-chat-id 145 --dir "$dir" 2>&1)" || fail "$script: $out"
        if [ "$(grep -c '^NOTIFY_TELEGRAM_TOKEN=' "$dir/.env" || true)" = 1 ] \
            && grep -qx "NOTIFY_TELEGRAM_TOKEN=$token" "$dir/.env" \
            && grep -qx 'NOTIFY_TELEGRAM_CHAT_ID=145' "$dir/.env" \
            && grep -qx 'KEEP=1' "$dir/.env" && grep -qx 'LAST=x' "$dir/.env"; then
            pass "$script: значения заменены, остальное цело"
        else
            fail "$script: .env: $(sed 's/=.*/=/' "$dir/.env" | tr '\n' ' ')"
        fi
        [ "$(stat -c %a "$dir/.env")" = 600 ] && pass "$script: .env с правами 600" || fail "$script: права .env"
        grep -qx 'compose up -d' "$dir/calls" && pass "$script: контейнеры обновлены" || fail "$script: нет compose up"
        [[ "$out" == *"$token"* ]] && fail "$script: токен в выводе" || pass "$script: токена нет в выводе"
        [ "$(find "$dir" -name '.env.*' | wc -l)" = 0 ] && pass "$script: временных файлов нет" \
            || fail "$script: остался временный файл"

        cp "$dir/.env" "$dir/before"
        if PATH="$bin:$PATH" bash "$root/$script" --telegram-only --telegram-token "$token" --dir "$dir" >/dev/null 2>&1; then
            fail "$script: токен без chat_id принят"
        elif PATH="$bin:$PATH" bash "$root/$script" --telegram-only --telegram-chat-id 1 \
            --telegram-token "$(printf '1:a\nEVIL=1')" --dir "$dir" >/dev/null 2>&1; then
            fail "$script: токен с переводом строки принят"
        elif cmp -s "$dir/.env" "$dir/before"; then
            pass "$script: неполные и неверные значения отвергнуты, .env не тронут"
        else
            fail "$script: .env изменился при отказе"
        fi
        rm -rf "$dir" "$bin"
    done
}

# --------------------------------------------- откат вместе с данными ----

rollback_agent() { # подпись образа; настоящие compose и данные, подменён только pull
    docker tag "nf-smoke-rollback:$1" nf-smoke-rollback:stable
    local rc=0
    (
        docker() {
            [ "$1" = pull ] && return 0
            command docker "$@"
        }
        export -f docker
        NOISEFLOOR_SERVICES_FILE="$RB_DIR/services" NOISEFLOOR_HEALTH_TIMEOUT=45 NOISEFLOOR_CANARY_TIMEOUT=45 \
            bash "$(cd "$(dirname "$0")/.." && pwd)/tools/noisefloor" "${@:2}"
    ) >"$RB_DIR/agent-$1.log" 2>&1 || rc=$?
    return "$rc"
}

rollback_peers() {
    curl -kfsS -H "Authorization: Bearer $CANARY_TOKEN" "https://127.0.0.1:$CANARY_PANEL_PORT/api/peers" || true
}

rollback_add_peer() {
    curl -kfsS -o /dev/null -X POST -H "Authorization: Bearer $CANARY_TOKEN" -H 'Content-Type: application/json' \
        -d "{\"name\":\"$1\"}" "https://127.0.0.1:$CANARY_PANEL_PORT/api/peers"
}

rollback_image() {
    docker inspect smoke-canary-panel --format '{{.Image}}'
}

test_rollback() {
    echo
    echo "Откат вместе с данными"
    canary_stand rollback 5 || return
    RB_DIR="$WORKDIR/rollback"
    local dir="$RB_DIR" repo=nf-smoke-rollback build="$WORKDIR/rollback-build"

    # Те же настройки, что у панели стенда, но под управлением compose.
    docker tag "$PANEL_IMAGE" "$repo:current"
    docker rm -f smoke-canary-panel >/dev/null
    cat > "$dir/docker-compose.yml" <<EOF
name: smoke-rollback
services:
  panel:
    image: $repo:current
    container_name: smoke-canary-panel
    cap_add: [NET_ADMIN, NET_RAW]
    devices: [/dev/net/tun]
    sysctls:
      net.ipv4.ip_forward: 1
    ports: ["127.0.0.1:$CANARY_PANEL_PORT:8000"]
    environment:
      LIVE_MANAGEMENT_ENABLED: "true"
      AUTO_APPLY_ON_START: "true"
      AWG_AUTO_UPDATE_ENABLED: "false"
      DEFAULT_SERVER_ADDRESS: 10.79.0.1/24
      DEFAULT_LISTEN_PORT: "51997"
      PUBLIC_HOST: 5.5.77.30
      CASCADE_PROBE_URL: http://5.5.77.10/generate_204
    volumes:
      - ./data:/opt/panel/data
      - ./awg_config:/etc/amnezia/amneziawg
    networks:
      smoke-canary-net: {ipv4_address: 5.5.77.30}
      smoke-canary-lan: {ipv4_address: 100.64.78.30}
networks:
  smoke-canary-net: {external: true}
  smoke-canary-lan: {external: true}
EOF
    (cd "$dir" && docker compose up -d >/dev/null 2>&1)
    if ! wait_for 90 canary_status_has '"canary_ok":true'; then
        fail "панель под compose не вернула зелёную канарейку"
        return
    fi
    printf 'panel=%s\n' "$dir" > "$dir/services"
    rollback_add_peer before-update
    local before
    before="$(rollback_image)"

    mkdir -p "$build/migration" "$build/cascade" "$build/good"
    {
        echo "FROM $PANEL_IMAGE"
        cat <<'EOF'
RUN sed -i 's|^def run_migrations() -> None:$|&\n    import pathlib, sqlite3\n    pathlib.Path("/opt/panel/data/logs").mkdir(exist_ok=True)\n    pathlib.Path("/opt/panel/data/logs/broken-migration").touch()\n    db = sqlite3.connect("/opt/panel/data/awg_panel.db")\n    db.execute("alter table peers rename to peers_new")\n    db.commit()\n    raise RuntimeError("сломанная миграция")|' /opt/panel/app/database.py
EOF
    } > "$build/migration/Dockerfile"
    {
        echo "FROM $PANEL_IMAGE"
        echo "RUN sed -i 's/^        port = parsed.port$/        port = 1/' /opt/panel/app/cascade.py"
    } > "$build/cascade/Dockerfile"
    printf 'FROM %s\nLABEL smoke=good\n' "$PANEL_IMAGE" > "$build/good/Dockerfile"
    local kind
    for kind in migration cascade good; do
        docker build -q -t "$repo:$kind" "$build/$kind" >/dev/null \
            || { fail "образ $kind не собрался"; return; }
    done

    # --- сломанная миграция портит базу и роняет новую версию ---
    mkdir "$dir/data.pre-old1" "$dir/data.pre-old2"
    touch -t 202001010000 "$dir/data.pre-old1"
    touch -t 202001020000 "$dir/data.pre-old2"
    if rollback_agent migration update panel; then
        fail "агент посчитал сломанную миграцию удачей"
        tail -5 "$dir/agent-migration.log"
    else
        pass "сломанная миграция: агент сообщил о неудаче"
    fi
    [ -e "$dir/data/logs/broken-migration" ] \
        && pass "миграция новой версии успела выполниться" \
        || { fail "сломанная миграция не запускалась, тест проверил не то"; tail -5 "$dir/agent-migration.log"; }
    [ "$(rollback_image)" = "$before" ] && pass "возвращён прежний образ" \
        || fail "после отката работает не прежний образ"
    [[ "$(rollback_peers)" == *before-update* ]] && pass "база возвращена: клиент на месте" \
        || { fail "база не возвращена: $(rollback_peers)"; tail -5 "$dir/agent-migration.log"; }
    if wait_for 60 canary_status_has '"canary_ok":true'; then
        pass "после отката каскад работает"
    else
        fail "после отката каскад не вернулся"
    fi
    [ -d "$dir/data.pre-old2" ] && [ ! -e "$dir/data.pre-old1" ] \
        && [ "$(find "$dir" -maxdepth 1 -name 'data.pre-*' | wc -l)" = 2 ] \
        && pass "хранятся две последние копии" || fail "копии: $(ls -d "$dir"/data.pre-*)"
    local snapshot
    snapshot="$(find "$dir" -maxdepth 1 -name 'data.pre-*' ! -name data.pre-old2)"
    [ -s "$snapshot/awg_panel.db" ] && [ ! -e "$snapshot/logs" ] && [ ! -e "$snapshot/canary" ] \
        && pass "в копии база, логов и каталога канарейки нет" || fail "состав копии: $(ls "$snapshot")"

    # --- новая версия здорова, но каскад не вернулся ---
    if rollback_agent cascade update panel; then
        fail "агент не заметил сломанный каскад"
        tail -5 "$dir/agent-cascade.log"
    else
        grep -q 'каскад работал до обновления' "$dir/agent-cascade.log" \
            && pass "здоровая панель с красной канарейкой откатывается" \
            || { fail "откат не из-за канарейки"; tail -5 "$dir/agent-cascade.log"; }
    fi
    [ "$(rollback_image)" = "$before" ] && pass "возвращён прежний образ" \
        || fail "после отката работает не прежний образ"
    grep -q 'каскад работал до обновления' "$dir/data/update-result.json" \
        && pass "причина записана в update-result.json" || fail "$(cat "$dir/data/update-result.json")"
    if wait_for 60 canary_status_has '"canary_ok":true'; then
        pass "каскад снова зелёный"
    else
        fail "каскад не вернулся после второго отката"
    fi

    # --- удачное обновление и откат руками через время ---
    if rollback_agent good update panel; then
        pass "исправная версия ставится, канарейка дождалась"
    else
        fail "исправная версия откатилась"
        tail -5 "$dir/agent-good.log"
        return
    fi
    [ "$(rollback_image)" != "$before" ] || fail "образ не сменился"
    rollback_add_peer after-update
    if rollback_agent good rollback panel; then
        if wait_for 45 curl -kfsS -o /dev/null "https://127.0.0.1:$CANARY_PANEL_PORT/api/health" \
            && [ "$(rollback_image)" = "$before" ] && [[ "$(rollback_peers)" != *after-update* ]]; then
            pass "откат руками вернул образ и данные на момент обновления"
        else
            fail "откат руками: $(rollback_peers)"
        fi
    else
        fail "откат руками не удался"
        tail -5 "$dir/agent-good.log"
    fi
    [ -s "$dir/data.before-rollback/awg_panel.db" ] \
        && pass "данные после обновления сохранены рядом" || fail "нет data.before-rollback"
    [ ! -e "$dir/.rollback-data" ] && pass "повторный откат данные не тронет" || fail "метка отката осталась"

    canary_cleanup
}

# --------------------------------------------------------------- установка ----

# Логику swap проверяем без настоящего swapon: ядро здесь общее с хостом.
test_install() {
    echo
    echo "Установщик"
    local root
    root="$(cd "$(dirname "$0")/.." && pwd)"

    grep -q 'oom_score_adj: -500' "$root/amneziawg-panel/docker-compose.yml" \
        && [ "$(grep -c 'oom_score_adj: -500' "$root/amneziawg-panel/install.sh")" = 1 ] \
        && pass "панель защищена от OOM в обоих compose" \
        || fail "нет oom_score_adj в compose панели"

    local fn out
    fn="$WORKDIR/swap.sh"
    {
        echo 'NO_SWAP=0; SWAP_FILE=/tmp/swapfile; FSTAB=/tmp/fstab'
        echo 'log() { :; }; warn() { echo "WARN $*"; }'
        sed -n '/^swap_size_mb() {/,/^ensure_swap$/p' "$root/amneziawg-panel/install.sh" | sed '$d'
    } > "$fn"

    out="$(bash -c ". '$fn'; swap_size_mb 1000000 0 20000; swap_size_mb 2097152 0 4000; \
        swap_size_mb 2097152 0 1000; swap_size_mb 2097153 0 20000; swap_size_mb 1000000 1024 20000" | tr '\n' ' ')"
    [ "$out" = "2048 1024 0 0 0 " ] \
        && pass "размер swap выбирается по памяти, swap и месту на диске" \
        || fail "swap_size_mb вернул: $out"

    out="$(docker run --rm -v "$fn:/swap.sh:ro" --entrypoint bash "$PANEL_IMAGE" -c '
        mkdir -p /tmp/bin; printf "#!/bin/sh\nexit 0\n" > /tmp/bin/swapon; chmod +x /tmp/bin/swapon
        export PATH=/tmp/bin:$PATH
        . /swap.sh
        swap_size_mb() { echo 16; }
        ensure_swap </dev/null
        ensure_swap </dev/null
        echo "mode=$(stat -c %a /tmp/swapfile) fstab=$(grep -c swapfile /tmp/fstab)"
        rm -f /tmp/swapfile; NO_SWAP=1; ensure_swap; echo "skipped=$([ -e /tmp/swapfile ] && echo no || echo yes)"
    ' 2>&1 | tail -2 | tr '\n' ' ')"
    [ "$out" = "mode=600 fstab=1 skipped=yes " ] \
        && pass "swap-файл с правами 600, в fstab один раз, --no-swap уважается" \
        || fail "ensure_swap: $out"
}

# ------------------------------------------- надзор за правилами, вживую ----

# Настоящая панель с живым управлением: свой netns, свой awg-интерфейс на
# amneziawg-go. Сеть хоста не затрагивается.
test_rules_supervision() {
    echo
    echo "Надзор за правилами  ($PANEL_IMAGE)"
    local dir="$WORKDIR/live" c=smoke-rules-panel port=29102
    mkdir -p "$dir/data" "$dir/awg_config" "$dir/bin"
    trap 'docker rm -f smoke-rules-panel >/dev/null 2>&1 || true; cleanup' EXIT

    # Подмена, которая по файлу-флагу делает любую заливку неудачной: так
    # проверяется, что панель показывает ошибку, а не только код возврата.
    cat > "$dir/bin/iptables-restore" <<'STUB'
#!/bin/sh
if [ -e /tmp/nf-fail ]; then
    echo "Extension TPROXY revision 0 not supported" >&2
    exit 2
fi
exec /usr/sbin/iptables-restore "$@"
STUB
    chmod +x "$dir/bin/iptables-restore"

    docker run -d --name "$c" --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun \
        -p "127.0.0.1:$port:8000" \
        -e LIVE_MANAGEMENT_ENABLED=true -e AUTO_APPLY_ON_START=true \
        -e AWG_AUTO_UPDATE_ENABLED=false -e AWG_INTERFACE=awg-smoke0 \
        -e DEFAULT_SERVER_ADDRESS=10.78.0.1/24 -e DEFAULT_LISTEN_PORT=51998 \
        -e PUBLIC_HOST=203.0.113.20 \
        -v "$dir/data:/opt/panel/data" -v "$dir/awg_config:/etc/amnezia/amneziawg" \
        "$PANEL_IMAGE" >/dev/null

    # Копия, а не bind mount: /tmp бывает смонтирован с noexec, и тогда sh
    # молча проходит мимо заглушки к настоящему iptables-restore.
    docker cp "$dir/bin/iptables-restore" "$c:/usr/local/bin/iptables-restore" >/dev/null

    if ! wait_for 60 test -s "$dir/data/INITIAL_ADMIN_PASSWORD.txt" \
        || ! wait_for 45 curl -kfsS -o /dev/null "https://127.0.0.1:$port/"; then
        fail "панель с живым управлением не поднялась"
        docker logs "$c" 2>&1 | tail -20
        return
    fi

    local pw token
    pw="$(grep -oE '[A-Za-z0-9_-]{12,}' "$dir/data/INITIAL_ADMIN_PASSWORD.txt" | head -1)"
    token="$(curl -kfsS -X POST "https://127.0.0.1:$port/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$pw\"}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' 2>/dev/null || true)"
    [ -n "$token" ] || { fail "не удалось войти в панель"; return; }

    status_has() {
        local body
        body="$(curl -kfsS -H "Authorization: Bearer $token" "https://127.0.0.1:$port/api/status")"
        [[ "$body" == *$1* ]]
    }
    rules_back() {
        docker exec "$c" sh -c 'iptables -S FORWARD | grep -q NOISEFLOOR-FWD'
    }

    if wait_for 30 rules_back; then
        pass "панель поставила правила при старте"
    else
        fail "правила не появились после старта"
        docker logs "$c" 2>&1 | tail -20
        return
    fi

    docker exec "$c" iptables -F FORWARD
    if wait_for 60 rules_back; then
        pass "снесённые правила вернулись не позже чем за 60 с"
    else
        fail "снесённые правила за 60 с не вернулись"
    fi

    curl -kfsS -H "Authorization: Bearer $token" "https://127.0.0.1:$port/api/status/metrics" \
        | grep -q '^noisefloor_rules_restored_total 1$' \
        && pass "восстановление видно в метриках" \
        || fail "noisefloor_rules_restored_total не вырос"

    docker exec "$c" touch /tmp/nf-fail
    docker exec "$c" iptables -F FORWARD
    if wait_for 60 status_has '"rules_ok":false*TPROXY'; then
        pass "панель показывает ошибку правил в статусе"
    else
        fail "ошибка правил не видна в статусе панели"
        docker logs "$c" 2>&1 | grep -v "GET /api" | tail -8
    fi

    docker exec "$c" rm /tmp/nf-fail
    if wait_for 60 status_has '"rules_ok":true'; then
        pass "после устранения причины ошибка ушла"
    else
        fail "ошибка правил висит и после восстановления"
    fi

    # Двадцать одновременных созданий: ни один клиент не должен потеряться,
    # ни адрес совпасть.
    local i
    for i in $(seq 1 20); do
        curl -kfsS -o /dev/null -X POST "https://127.0.0.1:$port/api/peers" \
            -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
            -d "{\"name\":\"p$i\"}" &
    done
    wait

    local live unique
    live="$(docker exec "$c" awg show awg-smoke0 peers | wc -l)"
    unique="$(curl -kfsS -H "Authorization: Bearer $token" "https://127.0.0.1:$port/api/peers" \
        | python3 -c 'import json,sys; print(len({p["address"] for p in json.load(sys.stdin)}))')"
    [ "$live" = 20 ] \
        && pass "20 параллельных созданий: все 20 пиров на интерфейсе" \
        || fail "параллельное создание: на интерфейсе $live пиров из 20"
    [ "$unique" = 20 ] \
        && pass "у всех 20 клиентов разные адреса" \
        || fail "параллельное создание: разных адресов $unique из 20"
}

# ------------------------------------------------------------------ main ----

echo "NOISEFLOOR · приёмочный тест"
dim "рабочий каталог: $WORKDIR"

case "${1:-}" in
    --relay-only) test_relay ;;
    --panel-only) test_panel; test_rules; test_rules_supervision; test_install ;;
    --rules-only) test_rules; test_rules_supervision ;;
    --install-only) test_install ;;
    --canary-only) test_canary ;;
    --failover-only) test_failover ;;
    --rotation-only) test_rotation "${2:-}" ;;
    --mtu-only) test_mtu ;;
    --ipv6-only) test_ipv6 ;;
    --split-only) test_split ;;
    --xudp-only) test_xudp ;;
    --selfcheck-only) test_selfcheck ;;
    --rollback-only) test_rollback ;;
    --notify-only) test_notify ;;
    --fallback-only) test_fallback ;;
    --telegram-install-only) test_install_telegram ;;
    "")           test_relay; test_panel; test_rules; test_rules_supervision; test_install; test_canary; test_failover; test_rotation; test_mtu; test_split; test_xudp; test_ipv6; test_selfcheck; test_rollback; test_notify; test_fallback; test_install_telegram ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
esac

echo
if [ "$FAILED" -eq 0 ]; then
    green "ВСЁ ЗЕЛЁНОЕ — сервисы разворачиваются с нуля и реально работают"
else
    red "ЕСТЬ ПАДЕНИЯ — деплоить нельзя"
fi
exit "$FAILED"
