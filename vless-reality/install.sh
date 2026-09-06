#!/usr/bin/env bash
#
# Установка релея NOISEFLOOR (VLESS + REALITY) на чистый Ubuntu/Debian.
#
# Это первый из двух серверов связки: выходной узел, чьим адресом клиенты
# видны в интернете. Второй — панель, ставится скриптом
# amneziawg-panel/install.sh; к ней подключаются устройства.
#
# Ставить релей нужно только если хотите каскад. Скрипт делает то, что описано
# в docs/DEPLOY.md, часть 1: ставит Docker, кладёт docker-compose.yml и .env,
# поднимает контейнер и показывает пароль администратора вместе с токеном
# синхронизации — тем самым, который потом вводится в панели.
#
# Пример:
#   ./install.sh --label "Амстердам"
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/noisefloor-relay}"
IMAGE="${IMAGE:-vbif666/noisefloor-vless-reality:latest}"
CONTAINER="NOISEFLOOR-vless-reality"

PUBLIC_HOST=""
LABEL="${LABEL:-relay}"
CODENAME="${CODENAME:-Relay-01}"
VLESS_PORT="${VLESS_PORT:-8443}"
PANEL_PORT="${PANEL_PORT:-8001}"
# Камуфляжный домен: под него маскируется соединение. dl.google.com проверен;
# www.microsoft.com брать нельзя — он отдаёт слишком большой сертификат, и
# библиотека REALITY молча рвёт каждое подключение (XTLS/Xray-core#6356).
REALITY_DEST="${REALITY_DEST:-dl.google.com:443}"
FORCE=0
SKIP_DOCKER=0

usage() {
    cat <<'EOF'
Установка релея NOISEFLOOR на чистый сервер.

  --public-host АДРЕС   IP или домен этого сервера (по умолчанию определяется сам)
  --label ИМЯ           как узел называется в списке серверов (по умолчанию relay)
  --codename ИМЯ        подпись в заголовке страницы релея (по умолчанию Relay-01)
  --vless-port ПОРТ     порт VLESS (по умолчанию 8443)
  --panel-port ПОРТ     порт страницы релея (по умолчанию 8001)
  --dest ДОМЕН:ПОРТ     камуфляжный домен (по умолчанию dl.google.com:443)
  --dir ПУТЬ            каталог установки (по умолчанию /opt/noisefloor-relay)
  --force               перезаписать существующий .env
  --skip-docker         не устанавливать Docker, считать что он есть
  -h, --help            эта справка
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --public-host) PUBLIC_HOST="$2"; shift 2 ;;
        --label)       LABEL="$2"; shift 2 ;;
        --codename)    CODENAME="$2"; shift 2 ;;
        --vless-port)  VLESS_PORT="$2"; shift 2 ;;
        --panel-port)  PANEL_PORT="$2"; shift 2 ;;
        --dest)        REALITY_DEST="$2"; shift 2 ;;
        --dir)         INSTALL_DIR="$2"; shift 2 ;;
        --force)       FORCE=1; shift ;;
        --skip-docker) SKIP_DOCKER=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "Неизвестный аргумент: $1" >&2; usage >&2; exit 2 ;;
    esac
done

log()  { printf '\033[1;36m[установка]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[внимание]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[ошибка]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "нужны права root: запустите через sudo"

if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *ubuntu*|*debian*) : ;;
        *) warn "система ${PRETTY_NAME:-неизвестная} не проверялась — ставим как на Debian/Ubuntu" ;;
    esac
fi

case "$REALITY_DEST" in
    www.microsoft.com*) die "www.microsoft.com как камуфляж не работает: сертификат больше лимита REALITY (XTLS/Xray-core#6356)" ;;
esac

# --- Docker -----------------------------------------------------------------

if [ "$SKIP_DOCKER" -eq 0 ] && ! command -v docker >/dev/null 2>&1; then
    log "ставлю Docker"
    curl -fsSL https://get.docker.com | sh >/dev/null
    systemctl enable --now docker >/dev/null 2>&1 || true
fi
command -v docker >/dev/null 2>&1 || die "Docker не установлен"
docker compose version >/dev/null 2>&1 || die "нет плагина docker compose — обновите Docker"

# --- Порты ------------------------------------------------------------------

port_busy() { ss -lnH -t "sport = :$1" 2>/dev/null | grep -q .; }

# Свои же порты, занятые уже работающим релеем, — не конфликт: значит это
# повторный запуск, и скрипт просто обновляет установку.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
    log "релей уже установлен — обновляю конфигурацию, ничего не сношу"
else
    if port_busy "$VLESS_PORT"; then
        die "TCP-порт $VLESS_PORT занят — выберите другой через --vless-port"
    fi
    if port_busy "$PANEL_PORT"; then
        die "TCP-порт $PANEL_PORT занят — выберите другой через --panel-port"
    fi
fi

# --- Публичный адрес --------------------------------------------------------

if [ -z "$PUBLIC_HOST" ]; then
    PUBLIC_HOST="$(curl -fsS --max-time 10 https://ifconfig.me 2>/dev/null || true)"
    [ -n "$PUBLIC_HOST" ] || PUBLIC_HOST="$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
    [ -n "$PUBLIC_HOST" ] || PUBLIC_HOST="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
    [ -n "$PUBLIC_HOST" ] && log "публичный адрес определён как $PUBLIC_HOST"
fi
# Пустой PUBLIC_HOST не смертелен: релей умеет определять адрес сам, но лучше
# зафиксировать — за NAT автоопределение врёт.
[ -n "$PUBLIC_HOST" ] || warn "не удалось определить публичный адрес — релей попробует определить его сам"

# --- Файлы ------------------------------------------------------------------

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

cat > docker-compose.yml <<EOF
services:
  relay:
    image: $IMAGE
    container_name: $CONTAINER
    restart: unless-stopped
    # Без лимита json-лог растёт бесконечно: страница релея опрашивает
    # состояние каждые несколько секунд, и каждый запрос — строка в логе.
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    network_mode: host
    environment:
      VLESS_PORT: "\${VLESS_PORT:-8443}"
      PANEL_PORT: "\${PANEL_PORT:-8001}"
      REALITY_DEST: "\${REALITY_DEST:-dl.google.com:443}"
      PUBLIC_HOST: "\${PUBLIC_HOST:-}"
      LABEL: "\${LABEL:-relay}"
      ADMIN_USERNAME: "\${ADMIN_USERNAME:-admin}"
      ADMIN_PASSWORD: "\${ADMIN_PASSWORD:-}"
      APP_CODENAME: "\${APP_CODENAME:-Relay-01}"
    volumes:
      - ./data:/data
EOF

if [ -f .env ] && [ "$FORCE" -eq 0 ]; then
    log ".env уже есть — оставляю как есть (перезаписать: --force)"
else
    umask 077
    cat > .env <<EOF
# Публичный адрес этого сервера — он попадает в параметры подключения.
PUBLIC_HOST=$PUBLIC_HOST
# Как узел называется в списке серверов клиентского приложения.
LABEL=$LABEL
APP_CODENAME=$CODENAME

VLESS_PORT=$VLESS_PORT
PANEL_PORT=$PANEL_PORT

# Камуфляжный домен: под обычный визит к нему маскируется соединение.
# Не ставьте www.microsoft.com — см. docs/DEPLOY.md.
REALITY_DEST=$REALITY_DEST

# Пустой пароль = сгенерируется при первом запуске и ляжет в
# data/INITIAL_ADMIN_PASSWORD.txt.
ADMIN_USERNAME=admin
ADMIN_PASSWORD=
EOF
    umask 022
fi

# --- Запуск -----------------------------------------------------------------

log "тяну образ"
docker compose pull -q 2>/dev/null || docker compose pull
log "запускаю релей"
docker compose up -d

log "жду, пока релей ответит"
ADMIN_PASSWORD=""
for _ in $(seq 1 60); do
    ADMIN_PASSWORD="$(docker exec "$CONTAINER" cat /data/INITIAL_ADMIN_PASSWORD.txt 2>/dev/null | tr -d '\r\n' || true)"
    [ -n "$ADMIN_PASSWORD" ] && curl -fsS -o /dev/null -u "admin:$ADMIN_PASSWORD" \
        "http://127.0.0.1:$PANEL_PORT/api/status" 2>/dev/null && break
    sleep 1
done
[ -n "$ADMIN_PASSWORD" ] || die "релей не поднялся; смотрите: docker logs $CONTAINER --tail 50"
curl -fsS -o /dev/null -u "admin:$ADMIN_PASSWORD" "http://127.0.0.1:$PANEL_PORT/api/status" 2>/dev/null \
    || die "релей не отвечает на $PANEL_PORT; смотрите: docker logs $CONTAINER --tail 50"

SYNC_TOKEN="$(docker exec "$CONTAINER" python3 -c \
    'import json;print(json.load(open("/data/creds.json")).get("sync_token",""))' 2>/dev/null | tr -d '\r\n' || true)"

# --- Итог -------------------------------------------------------------------

echo
printf '\033[1;32m=== Релей установлен ===\033[0m\n\n'
printf '  Страница:  http://%s:%s\n' "${PUBLIC_HOST:-АДРЕС_СЕРВЕРА}" "$PANEL_PORT"
printf '  Логин:     admin\n'
printf '  Пароль:    %s\n' "$ADMIN_PASSWORD"
printf '  Каталог:   %s\n' "$INSTALL_DIR"
printf '  VLESS:     порт %s, камуфляж %s\n' "$VLESS_PORT" "$REALITY_DEST"
echo
if [ -n "$SYNC_TOKEN" ]; then
    printf '  Токен синхронизации (его вводят в панели, блок «Каскад»):\n    %s\n\n' "$SYNC_TOKEN"
    printf '  Установка панели одной командой, уже связанной с этим релеем:\n'
    printf '    ./install.sh --relay http://%s:%s --relay-token %s\n' \
        "${PUBLIC_HOST:-АДРЕС_ЭТОГО_СЕРВЕРА}" "$PANEL_PORT" "$SYNC_TOKEN"
else
    warn "токен синхронизации не прочитался — он есть на странице релея"
fi
echo
printf '  Ссылки подключения и QR на странице нет намеренно: в ссылке лежит UUID,\n'
printf '  то есть готовый доступ к релею. Если релей нужен как самостоятельный\n'
printf '  эндпоинт, ссылку отдаёт API:\n'
printf '    curl -s -u admin:ПАРОЛЬ http://127.0.0.1:%s/api/status | python3 -c '"'"'import json,sys; print(json.load(sys.stdin)["vless_url"])'"'"'\n' "$PANEL_PORT"
echo
printf '\033[1;33m  Страница релея открыта в интернет по HTTP без шифрования.\033[0m Закройте её\n'
printf '  фаерволом — снаружи нужен только порт %s (VLESS).\n' "$VLESS_PORT"
echo
