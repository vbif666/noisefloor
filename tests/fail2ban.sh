#!/usr/bin/env bash
# fail2ban: перебор паролей SSH → бан в nftables.
#
# Контейнер поднимается в своей bridge-сети, поэтому баны ложатся в nftables
# его пространства имён, а не хоста: тест безопасен на боевом сервере.
# Вместо журнала хоста — свой auth.log, в который дописываются строки
# неудачных входов в двух видах (sshd и sshd-session из OpenSSH 9.8+).
#
# Использование:
#   F2B_IMAGE=vbif666/noisefloor-fail2ban:ci tests/fail2ban.sh

set -euo pipefail

F2B_IMAGE="${F2B_IMAGE:-vbif666/noisefloor-fail2ban:latest}"
NAME=nf-f2b-test
ATTACKER=203.0.113.7       # sshd
ATTACKER2=203.0.113.8      # sshd-session
FRIEND=198.51.100.9        # в IGNOREIP
VPN_CLIENT=10.13.13.5      # сеть клиентов, в исключениях всегда

WORKDIR="$(mktemp -d /tmp/noisefloor-f2b.XXXXXX)"
FAILED=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }
pass() { green "  ✓ $*"; }
fail() { red   "  ✗ $*"; FAILED=1; }

cleanup() {
    if [ "$FAILED" -ne 0 ]; then
        dim "  логи контейнера:"
        docker logs "$NAME" 2>&1 | tail -30 | sed 's/^/    /'
    fi
    dim "  очистка…"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
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

f2b() { docker exec "$NAME" fail2ban-client "$@"; }
# Вывод сначала целиком в переменную: grep -q в конвейере закрывает его
# раньше времени, и при pipefail проверка падает на SIGPIPE.
banned() { local out; out=$(f2b get sshd banned) && grep -q "'$1'" <<<"$out"; }
in_nft() { local out; out=$(docker exec "$NAME" nft list ruleset) && grep -qw "$1" <<<"$out"; }

fail_lines() { # адрес демон количество
    local i
    for i in $(seq "$3"); do
        printf '%s testhost %s[%d]: Failed password for root from %s port %d ssh2\n' \
            "$(date '+%b %e %H:%M:%S')" "$2" "$((1000 + i))" "$1" "$((40000 + i))"
    done >> "$WORKDIR/log/auth.log"
}

echo "fail2ban  ($F2B_IMAGE)"

mkdir -p "$WORKDIR/log" "$WORKDIR/data"
: > "$WORKDIR/log/auth.log"
fail_lines 192.0.2.1 sshd 1   # чтобы файл не был пустым и auto выбрал его

docker run -d --name "$NAME" --cap-add NET_ADMIN --cap-add NET_RAW \
    -e MAXRETRY=3 -e IGNOREIP="$FRIEND" \
    -v "$WORKDIR/log:/host/log:ro" -v "$WORKDIR/data:/var/lib/fail2ban" \
    "$F2B_IMAGE" >/dev/null

if wait_for 30 f2b ping; then pass "сервер отвечает"; else fail "fail2ban не поднялся"; exit 1; fi
if grep -q "sshd: файл /host/log/auth.log" <<<"$(docker logs "$NAME" 2>&1)"; then
    pass "SSH_LOG=auto выбрал auth.log"
else
    fail "auto не выбрал auth.log"
fi
if f2b status sshd >/dev/null 2>&1; then pass "джейл sshd включён"; else fail "нет джейла sshd"; fi

fail_lines "$ATTACKER" sshd 4
fail_lines "$ATTACKER2" sshd-session 4
fail_lines "$FRIEND" sshd 6
fail_lines "$VPN_CLIENT" sshd 6

if wait_for 30 banned "$ATTACKER"; then pass "$ATTACKER забанен (sshd)"; else fail "$ATTACKER не забанен"; fi
if wait_for 10 banned "$ATTACKER2"; then pass "$ATTACKER2 забанен (sshd-session)"; else fail "$ATTACKER2 не забанен"; fi
if in_nft "$ATTACKER"; then
    pass "адрес в nftables (inet f2b-table)"
else
    fail "в nftables адреса нет"
    docker exec "$NAME" nft list ruleset | sed 's/^/    /'
fi
if banned "$FRIEND"; then fail "$FRIEND из IGNOREIP забанен"; else pass "IGNOREIP не банится"; fi
if banned "$VPN_CLIENT"; then fail "клиент VPN $VPN_CLIENT забанен"; else pass "сеть VPN не банится"; fi

# Баны переживают перезапуск: история в /var/lib/fail2ban (том ./data).
docker restart "$NAME" >/dev/null
if wait_for 30 f2b ping && wait_for 20 banned "$ATTACKER"; then
    pass "бан восстановлен после перезапуска"
else
    fail "после перезапуска бана нет"
fi

if f2b set sshd unbanip "$ATTACKER" >/dev/null && ! in_nft "$ATTACKER"; then
    pass "unbanip снимает правило"
else
    fail "unbanip не сработал"
fi

if [ "$FAILED" -eq 0 ]; then green "fail2ban: всё прошло"; else red "fail2ban: есть ошибки"; fi
exit "$FAILED"
