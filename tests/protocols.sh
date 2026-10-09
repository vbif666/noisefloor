#!/usr/bin/env bash
# Протоколы клиентов с настоящим рукопожатием: AmneziaWG 2.0, AmneziaWG 1.x и
# обычный WireGuard.
#
# Юнит-тесты проверяют текст конфигов, но не то, что клиент с таким конфигом
# действительно подключится. Здесь в отдельной docker-сети поднимается панель
# с живым управлением, в ней включаются дополнительные протоколы, и к каждому
# интерфейсу подключается свой клиент. Успех — только прошедший через туннель
# HTTP-запрос к панели по её адресу внутри туннеля.
#
# Сеть хоста не трогается: всё в bridge-сети и в пространствах имён
# контейнеров, поэтому тест безопасен на боевом сервере.
#
# Использование:
#   PANEL_IMAGE=vbif666/noisefloor-amneziawg-panel:ci tests/protocols.sh

set -euo pipefail

PANEL_IMAGE="${PANEL_IMAGE:-vbif666/noisefloor-amneziawg-panel:latest}"
NET=nf-proto-test
SUBNET=172.29.99.0/24
SERVER_IP=172.29.99.10
SERVER=nf-proto-server
PANEL="https://$SERVER_IP:8000"

WORKDIR="$(mktemp -d /tmp/noisefloor-proto.XXXXXX)"
FAILED=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }
pass() { green "  ✓ $*"; }
fail() { red   "  ✗ $*"; FAILED=1; }

cleanup() {
    dim "  очистка…"
    docker rm -f "$SERVER" nf-proto-c-awg2 nf-proto-c-awg1 nf-proto-c-wg >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

wait_for() {
    local deadline=$(( $(date +%s) + $1 )); shift
    until "$@" >/dev/null 2>&1; do
        [ "$(date +%s)" -ge "$deadline" ] && return 1
        sleep 1
    done
}

json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

echo "Протоколы клиентов  ($PANEL_IMAGE)"

docker network create --subnet "$SUBNET" "$NET" >/dev/null
mkdir -p "$WORKDIR/data"
docker run -d --name "$SERVER" --network "$NET" --ip "$SERVER_IP" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -e LIVE_MANAGEMENT_ENABLED=true -e AUTO_APPLY_ON_START=true \
    -e AWG_AUTO_UPDATE_ENABLED=false -e EGRESS_INTERFACE=eth0 \
    -e DEFAULT_LISTEN_PORT=51999 \
    -v "$WORKDIR/data:/opt/panel/data" \
    "$PANEL_IMAGE" >/dev/null

if ! wait_for 60 test -s "$WORKDIR/data/INITIAL_ADMIN_PASSWORD.txt" \
   || ! wait_for 45 curl -kfsS -o /dev/null "$PANEL/"; then
    fail "панель не поднялась"
    docker logs "$SERVER" 2>&1 | tail -20
    exit 1
fi
pw="$(grep -oE '[A-Za-z0-9_-]{12,}' "$WORKDIR/data/INITIAL_ADMIN_PASSWORD.txt" | head -1)"
token="$(curl -kfsS -X POST "$PANEL/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$pw\"}" | json 'd["access_token"]')"
api() {
    local method="$1" path="$2"; shift 2
    curl -kfsS -X "$method" "$PANEL/api$path" -H "Authorization: Bearer $token" \
        -H 'Content-Type: application/json' "$@"
}
pass "панель поднялась с живым управлением"

api PUT /server -d "{\"endpoint_host\":\"$SERVER_IP\"}" >/dev/null

# --- включение протоколов ----------------------------------------------------

for proto in awg1 wg; do
    up="$(api PUT "/tunnels/$proto" -d '{"enabled":true}' | json 'd["interface_up"]')"
    [ "$up" = "True" ] && pass "$proto: интерфейс поднялся" || fail "$proto: интерфейс не поднялся"
done

clash="$(api PUT /tunnels/wg -d '{"listen_port":51999}' -o /dev/null -w '%{http_code}' || true)"
[ "$clash" = "400" ] && pass "порт основного интерфейса протоколу не отдаётся" \
                     || fail "порт основного интерфейса удалось занять (HTTP $clash)"

# Правила ставятся одним вызовом на все интерфейсы. Если PostUp основного
# интерфейса их не перезапустил, клиенты дополнительных останутся без NAT.
rules="$(docker exec "$SERVER" iptables -S NOISEFLOOR-FWD 2>/dev/null || true)"
for iface in awg0 awg-v1 wg-plain; do
    printf '%s' "$rules" | grep -q -- "-i $iface -j ACCEPT" \
        && pass "правила форвардинга есть для $iface" \
        || fail "нет правил форвардинга для $iface"
done

# --- клиенты -----------------------------------------------------------------

declare -A TUNNEL_IP=([awg2]=10.13.13.1 [awg1]=10.13.14.1 [wg]=10.13.15.1)

for proto in awg2 awg1 wg; do
    cfg="$(api POST /peers -d "{\"name\":\"proto-$proto\",\"protocol\":\"$proto\"}" | json 'd["config_text"]')"
    server_ip="${TUNNEL_IP[$proto]}"

    case "$proto" in
        wg)   printf '%s\n' "$cfg" | grep -qE '^(Jc|S1|H1|I1) =' \
                  && fail "wg: в конфиге обычного WireGuard есть поля AmneziaWG" \
                  || pass "wg: конфиг чистый WireGuard" ;;
        awg1) printf '%s\n' "$cfg" | grep -qE '^(S3|S4|I1) =' \
                  && fail "awg1: в конфиге 1.x есть поля 2.0" \
                  || pass "awg1: в конфиге только поля 1.x" ;;
    esac

    # Весь трафик в туннель клиенту не нужен: хватит адреса сервера. DNS
    # убираем — awg-quick без resolvconf на нём падает.
    printf '%s\n' "$cfg" \
        | sed -e "s|^AllowedIPs = .*|AllowedIPs = $server_ip/32|" -e '/^DNS = /d' \
        > "$WORKDIR/c-$proto.conf"

    docker run -d --name "nf-proto-c-$proto" --network "$NET" \
        --cap-add NET_ADMIN --device /dev/net/tun \
        -v "$WORKDIR/c-$proto.conf:/tmp/c0.conf:ro" \
        --entrypoint sh "$PANEL_IMAGE" -c 'sleep 300' >/dev/null
    docker exec "nf-proto-c-$proto" sh -c \
        'mkdir -p /etc/amnezia/amneziawg && cp /tmp/c0.conf /etc/amnezia/amneziawg/c0.conf && chmod 600 /etc/amnezia/amneziawg/c0.conf && awg-quick up c0' \
        >/dev/null 2>&1 || { fail "$proto: клиент не поднял интерфейс"; continue; }

    if wait_for 20 docker exec "nf-proto-c-$proto" python3 -c \
        "import urllib.request; import ssl; urllib.request.urlopen('https://$server_ip:8000/api/health', timeout=3, context=ssl._create_unverified_context())"; then
        pass "$proto: рукопожатие прошло, панель отвечает через туннель ($server_ip)"
    else
        fail "$proto: через туннель до $server_ip не достучаться"
        docker exec "nf-proto-c-$proto" awg show c0 2>&1 | sed 's/^/      /'
    fi
done

# Клиент 2.0 не должен проходить на интерфейс обычного WireGuard: иначе
# маскировка ничего не значит, и разделение по интерфейсам лишнее.
wg_port="$(api GET /tunnels | json '[t["listen_port"] for t in d if t["protocol"]=="wg"][0]')"
docker exec nf-proto-c-awg2 sh -c "awg-quick down c0 >/dev/null 2>&1; sed -i 's|^Endpoint = .*|Endpoint = $SERVER_IP:$wg_port|' /etc/amnezia/amneziawg/c0.conf && awg-quick up c0 >/dev/null 2>&1"
if docker exec nf-proto-c-awg2 python3 -c \
    "import urllib.request; import ssl; urllib.request.urlopen('https://10.13.13.1:8000/api/health', timeout=5, context=ssl._create_unverified_context())" >/dev/null 2>&1; then
    fail "клиент AmneziaWG 2.0 прошёл на порт обычного WireGuard"
else
    pass "клиент AmneziaWG 2.0 на порт обычного WireGuard не проходит"
fi

online="$(api GET /peers | json 'sorted(p["protocol"] for p in d if p["online"])')"
[ "$online" = "['awg1', 'awg2', 'wg']" ] && pass "панель видит онлайн клиентов всех протоколов" \
    || fail "онлайн в панели: $online"

# --- настоящий WireGuard -----------------------------------------------------
# Клиенты выше — amneziawg-go с чистым конфигом. Это тот же протокол, но
# проверить стоит и эталон: модуль ядра и стандартные wireguard-tools, как
# у роутеров и приложения WireGuard. Интерфейс создаётся в пространстве имён
# контейнера, хост не затрагивается. Без модуля в ядре — пропускаем.
if modinfo wireguard >/dev/null 2>&1; then
    cfg="$(api POST /peers -d '{"name":"proto-vanilla","protocol":"wg"}' | json 'd["config_text"]')"
    addr="$(printf '%s\n' "$cfg" | sed -n 's/^Address = //p')"
    printf '%s\n' "$cfg" \
        | sed -e '/^Address = /d' -e '/^DNS = /d' -e '/^MTU = /d' \
              -e "s|^AllowedIPs = .*|AllowedIPs = 10.13.15.1/32|" \
        > "$WORKDIR/vanilla.conf"
    if docker run --rm --network "$NET" --cap-add NET_ADMIN \
        -v "$WORKDIR/vanilla.conf:/wg.conf:ro" alpine:3 sh -c "
            apk add -q wireguard-tools-wg >/dev/null 2>&1 || exit 2
            ip link add wg0 type wireguard || exit 3
            wg setconf wg0 /wg.conf || exit 4
            ip addr add $addr dev wg0 && ip link set wg0 up
            ip route add 10.13.15.1/32 dev wg0
            for i in 1 2 3 4 5 6 7 8 9 10; do
                wget -q -T 3 --no-check-certificate -O /dev/null https://10.13.15.1:8000/api/health && exit 0
                sleep 1
            done
            wg show wg0; exit 1" >/dev/null 2>&1; then
        pass "стандартный WireGuard (модуль ядра) подключается к wg-plain"
    else
        fail "стандартный WireGuard не подключился к wg-plain"
    fi
else
    dim "  модуля wireguard в ядре нет — проверку эталонным клиентом пропускаю"
fi

# --- выключение --------------------------------------------------------------

api PUT /tunnels/wg -d '{"enabled":false}' >/dev/null
docker exec "$SERVER" ip link show wg-plain >/dev/null 2>&1 \
    && fail "wg: интерфейс остался после выключения" \
    || pass "wg: выключение опускает интерфейс"

code="$(api POST /peers -d '{"name":"late","protocol":"wg"}' -o /dev/null -w '%{http_code}' || true)"
[ "$code" = "400" ] && pass "клиента выключенного протокола создать нельзя" \
                    || fail "клиент выключенного протокола создался (HTTP $code)"

echo
if [ "$FAILED" = 0 ]; then green "Все проверки протоколов прошли"; else red "Есть провалы"; exit 1; fi
