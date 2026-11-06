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
#   tests/smoke.sh --rotation-only [секунд загрузки, по умолчанию 60]
#   tests/smoke.sh --selfcheck-only
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
    docker rm -f smoke-canary smoke-canary-panel smoke-canary-relay smoke-canary-relay2 smoke-canary-web >/dev/null 2>&1 || true
    docker network rm smoke-canary-net smoke-canary-lan >/dev/null 2>&1 || true
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
        sock.sendto(data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01" + data[8:], addr)

threading.Thread(target=dns, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
PY
    docker run -d --name smoke-canary-web --network "$net" --ip 5.5.77.10 \
        -v "$dir/web.py:/web.py:ro" --entrypoint python "$PANEL_IMAGE" /web.py >/dev/null

    docker run -d --name smoke-canary-relay --network "$net" --ip 5.5.77.20 \
        -e LABEL=smoke-canary -e APP_CODENAME=SmokeCanary -e PUBLIC_HOST=5.5.77.20 \
        -e ADMIN_PASSWORD=smoke-relay-pass \
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
        -e CASCADE_PROBE_URL=http://5.5.77.10/generate_204 \
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
        -e CANARY_DOWNLOAD_URL=http://5.5.77.10/1mb -e CANARY_DNS_SERVER=5.5.77.10 \
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
    --selfcheck-only) test_selfcheck ;;
    "")           test_relay; test_panel; test_rules; test_rules_supervision; test_install; test_canary; test_failover; test_rotation; test_mtu; test_selfcheck ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
esac

echo
if [ "$FAILED" -eq 0 ]; then
    green "ВСЁ ЗЕЛЁНОЕ — сервисы разворачиваются с нуля и реально работают"
else
    red "ЕСТЬ ПАДЕНИЯ — деплоить нельзя"
fi
exit "$FAILED"
