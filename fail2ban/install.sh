#!/usr/bin/env bash
#
# Установка fail2ban NOISEFLOOR: бан адресов, которые перебирают пароли SSH.
#
# Ставится рядом с панелью или релеем (или на любой сервер с Docker) в свой
# каталог, со своим docker-compose.yml — панель и `noisefloor update` его не
# касаются. Повторный запуск обновляет образ и досогласовывает настройки,
# чужой .env не переписывается без --force.
#
# Пример:
#   ./install.sh                         # порт SSH определится сам
#   ./install.sh --ignore 203.0.113.10   # свой адрес никогда не банить
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/noisefloor-fail2ban}"
IMAGE="${IMAGE:-vbif666/noisefloor-fail2ban:latest}"
CONTAINER="NOISEFLOOR-fail2ban"

SSH_PORT=""
IGNOREIP=""
BANTIME=1h
FINDTIME=10m
MAXRETRY=5
FORCE=0

usage() {
    cat <<'EOF'
Установка fail2ban NOISEFLOOR (защита SSH от перебора паролей).

  --ssh-port ПОРТ      порт SSH (по умолчанию — из sshd -T, иначе 22)
  --ignore "А Б"       адреса/сети, которые не банить никогда (через пробел)
  --bantime СРОК       первый бан (по умолчанию 1h; повторные — вдвое дольше, до 1w)
  --findtime СРОК      окно подсчёта попыток (по умолчанию 10m)
  --maxretry N         попыток до бана (по умолчанию 5)
  --dir ПУТЬ           каталог установки (по умолчанию /opt/noisefloor-fail2ban)
  --force              перезаписать существующий .env
  -h, --help           эта справка
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        --ignore)   IGNOREIP="$2"; shift 2 ;;
        --bantime)  BANTIME="$2"; shift 2 ;;
        --findtime) FINDTIME="$2"; shift 2 ;;
        --maxretry) MAXRETRY="$2"; shift 2 ;;
        --dir)      INSTALL_DIR="$2"; shift 2 ;;
        --force)    FORCE=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "неизвестный параметр: $1" >&2; usage; exit 1 ;;
    esac
done

log()  { printf '\033[1;32m[fail2ban]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[fail2ban]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail2ban] ОШИБКА:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "запустите от root"
command -v docker >/dev/null 2>&1 || die "Docker не установлен — сначала поставьте панель или релей"
docker compose version >/dev/null 2>&1 || die "нет плагина docker compose — обновите Docker"

# fail2ban на хосте и в контейнере будут банить в разные таблицы и путаться
# в одних и тех же адресах — оставляем один.
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    die "на хосте уже работает fail2ban (systemctl status fail2ban) — остановите его или не ставьте этот"
fi

if [ -z "$SSH_PORT" ]; then
    SSH_PORT=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | paste -sd, -)
    SSH_PORT="${SSH_PORT:-22}"
fi
log "порт SSH: $SSH_PORT"

if [ ! -s /var/log/auth.log ] && [ -z "$(ls -A /var/log/journal /run/log/journal 2>/dev/null)" ]; then
    die "не нашёл журнал sshd: нет ни /var/log/auth.log, ни журнала systemd"
fi

# Адрес текущей SSH-сессии — в исключения, чтобы случайно не запереть себя.
if [ -n "${SSH_CLIENT:-}" ]; then
    me="${SSH_CLIENT%% *}"
    case " $IGNOREIP " in *" $me "*) ;; *) IGNOREIP="${IGNOREIP:+$IGNOREIP }$me" ;; esac
fi

mkdir -p "$INSTALL_DIR/data"
cd "$INSTALL_DIR"

curl -fsSL "https://raw.githubusercontent.com/vbif666/noisefloor/master/fail2ban/docker-compose.yml" -o docker-compose.yml.tmp \
    || die "не удалось скачать docker-compose.yml"
sed -i "s#image: vbif666/noisefloor-fail2ban:latest#image: $IMAGE#" docker-compose.yml.tmp
mv docker-compose.yml.tmp docker-compose.yml

if [ -f .env ] && [ "$FORCE" -eq 0 ]; then
    log ".env уже есть — оставляю как есть (перезаписать: --force)"
else
    cat > .env <<EOF
# Настройки fail2ban NOISEFLOOR. После правки: docker compose up -d
SSH_PORT=$SSH_PORT
# auto — /var/log/auth.log, если он есть, иначе журнал systemd; journal; или путь
SSH_LOG=auto
BANTIME=$BANTIME
FINDTIME=$FINDTIME
MAXRETRY=$MAXRETRY
# Никогда не банить (через пробел). Сеть клиентов VPN 10.13.0.0/16 не банится всегда.
IGNOREIP="$IGNOREIP"
EOF
fi

log "скачиваю образ"
docker compose pull -q
docker compose up -d >/dev/null

for _ in $(seq 30); do
    docker exec "$CONTAINER" fail2ban-client ping >/dev/null 2>&1 && break
    sleep 1
done
docker exec "$CONTAINER" fail2ban-client status sshd >/dev/null 2>&1 \
    || die "fail2ban не поднялся: docker logs $CONTAINER"

echo
printf '\033[1;32m=== fail2ban работает ===\033[0m\n\n'
docker exec "$CONTAINER" fail2ban-client status sshd | sed 's/^/  /'
echo
printf '  Каталог:   %s (настройки — .env, после правки docker compose up -d)\n' "$INSTALL_DIR"
printf '  Баны:      docker exec %s fail2ban-client status sshd\n' "$CONTAINER"
printf '  Разбанить: docker exec %s fail2ban-client set sshd unbanip АДРЕС\n' "$CONTAINER"
printf '  Обновить:  cd %s && docker compose pull && docker compose up -d\n' "$INSTALL_DIR"
echo
