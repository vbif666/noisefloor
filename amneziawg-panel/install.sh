#!/usr/bin/env bash
#
# Установка панели NOISEFLOOR (AmneziaWG + каскад) на чистый Ubuntu/Debian.
#
# Это сервер 1 связки — точка входа, к которой подключаются устройства. Нужен
# всегда. Сервер 2 — релей, выходной узел, ставится скриптом
# vless-reality/install.sh; он нужен, только если хотите каскад.
#
# Скрипт делает ровно то, что описано в docs/DEPLOY.md, часть 2: ставит Docker,
# включает форвардинг, кладёт docker-compose.yml и .env, поднимает контейнер и
# показывает пароль администратора. Повторный запуск ничего не ломает: чужой
# .env не переписывается без --force.
#
# Пример:
#   ./install.sh                                  # просто VPN
#   ./install.sh --relay http://СЕРВЕР2:8001 --relay-token ТОКЕН  # с каскадом
#
# Второй вызов можно сделать и позже, когда релей уже поставлен: повторный
# запуск не сносит работающую панель, а только досогласовывает настройки.
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/noisefloor-panel}"
IMAGE="${IMAGE:-vbif666/noisefloor-amneziawg-panel:latest}"
CONTAINER="NOISEFLOOR-amneziawg-panel"
PANEL_PORT=8000               # порт панели зашит в образ, менять нечем

PUBLIC_HOST=""
RELAY_URL=""
RELAY_TOKEN=""
INTERCEPT_MODE=""
AWG_INTERFACE="${AWG_INTERFACE:-awg0}"
LISTEN_PORT="${LISTEN_PORT:-443}"
SERVER_ADDRESS="${SERVER_ADDRESS:-10.13.13.1/24}"
DNS="${DNS:-1.1.1.1}"
BACKUP_PASSPHRASE="${BACKUP_PASSPHRASE:-}"
NO_BACKUP_PASSPHRASE=0
FORCE=0
SKIP_DOCKER=0

usage() {
    cat <<'EOF'
Установка панели NOISEFLOOR на чистый сервер.

  --public-host АДРЕС      IP или домен этого сервера (по умолчанию IPv4, при нескольких — спросит)
  --relay URL              адрес панели релея, например http://203.0.113.10:8001
  --relay-token ТОКЕН      токен синхронизации со страницы релея
  --intercept-mode РЕЖИМ   tproxy | redirect (по умолчанию выбирается по ядру)
  --interface ИМЯ          имя VPN-интерфейса (по умолчанию awg0)
  --listen-port ПОРТ       UDP-порт VPN (по умолчанию 443)
  --address CIDR           адрес сервера внутри туннеля (по умолчанию 10.13.13.1/24)
  --dns АДРЕС              DNS для клиентов (по умолчанию 1.1.1.1)
  --backup-passphrase X    пароль шифрования резервных копий (иначе сгенерируется)
  --no-backup-passphrase   не шифровать резервные копии (внутри — ключи клиентов)
  --dir ПУТЬ               каталог установки (по умолчанию /opt/noisefloor-panel)
  --force                  перезаписать существующий .env
  --skip-docker            не устанавливать Docker, считать что он есть
  -h, --help               эта справка

Каскад можно включить и потом — в панели, вкладка «Сервер».
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --public-host)          PUBLIC_HOST="$2"; shift 2 ;;
        --relay)                RELAY_URL="$2"; shift 2 ;;
        --relay-token)          RELAY_TOKEN="$2"; shift 2 ;;
        --intercept-mode)       INTERCEPT_MODE="$2"; shift 2 ;;
        --interface)            AWG_INTERFACE="$2"; shift 2 ;;
        --listen-port)          LISTEN_PORT="$2"; shift 2 ;;
        --address)              SERVER_ADDRESS="$2"; shift 2 ;;
        --dns)                  DNS="$2"; shift 2 ;;
        --backup-passphrase)    BACKUP_PASSPHRASE="$2"; shift 2 ;;
        --no-backup-passphrase) NO_BACKUP_PASSPHRASE=1; shift ;;
        --dir)                  INSTALL_DIR="$2"; shift 2 ;;
        --force)                FORCE=1; shift ;;
        --skip-docker)          SKIP_DOCKER=1; shift ;;
        -h|--help)              usage; exit 0 ;;
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

# --- Docker -----------------------------------------------------------------

if [ "$SKIP_DOCKER" -eq 0 ] && ! command -v docker >/dev/null 2>&1; then
    log "ставлю Docker"
    curl -fsSL https://get.docker.com | sh >/dev/null
    systemctl enable --now docker >/dev/null 2>&1 || true
fi
command -v docker >/dev/null 2>&1 || die "Docker не установлен"
docker compose version >/dev/null 2>&1 || die "нет плагина docker compose — обновите Docker"

# --- Что мешает жить: занятые порты, отсутствующий tun, выключенный форвардинг

port_busy() { ss -lnH "$1" "sport = :$2" 2>/dev/null | grep -q .; }

# Порты и интерфейс занимает в том числе уже установленная панель — для неё
# это не конфликт, а повторный запуск: скрипт тогда работает как обновление.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
    ALREADY_INSTALLED=1
    log "панель уже установлена — обновляю конфигурацию, ничего не сношу"
else
    ALREADY_INSTALLED=0
    if port_busy -t "$PANEL_PORT"; then
        die "TCP-порт $PANEL_PORT уже занят — панель не поднимется (она слушает его в сети хоста)"
    fi
    if port_busy -u "$LISTEN_PORT"; then
        die "UDP-порт $LISTEN_PORT занят — выберите другой через --listen-port"
    fi
    if ip link show "$AWG_INTERFACE" >/dev/null 2>&1; then
        die "интерфейс $AWG_INTERFACE уже существует — выберите другое имя через --interface"
    fi
fi

[ -e /dev/net/tun ] || modprobe tun 2>/dev/null || true
[ -e /dev/net/tun ] || die "нет /dev/net/tun — на этом ядре VPN не поднимется"

# --- Сетевые настройки ядра -------------------------------------------------
#
# Пишем одним файлом в sysctl.d: свой файл переживёт обновление системы, и
# всё, что мы трогаем, видно в одном месте.
#
# Зачем каждая строка:
#   ip_forward           — без него клиенты подключатся, но интернета не будет.
#   bbr + fq             — дальнее плечо каскада (панель → релей) это одно
#                          TCP-соединение через полконтинента. cubic на такой
#                          дистанции обваливает окно от каждой потери; замер на
#                          связке 147→Амстердам: 10-11 МБ/с на cubic против
#                          13-15 МБ/с на bbr при прочих равных.
#   rmem/wmem            — 208 КБ по умолчанию меньше, чем произведение полосы
#                          на задержку этого плеча, то есть окно упирается в
#                          буфер раньше, чем в канал.
#   nf_conntrack_max     — на гигабайте памяти ядро берёт 7-8 тысяч записей.
#                          Десяток активных клиентов их выбирает, и дальше
#                          новые соединения молча теряются: на проде набежало
#                          331 тысяча дропнутых пакетов (conntrack -S,
#                          insert_failed) — те самые "иногда не открывается".
#   tcp_timeout_established — пять суток на запись о соединении, которого
#                          давно нет, — это и есть переполнение таблицы.
#   tcp_be_liberal       — пакеты вне окна (обычная вещь при ретрансмитах на
#                          длинном плече) иначе считаются INVALID.
#   tcp_mtu_probing      — страховка от PMTU black hole внутри туннеля.
#   slow_start_after_idle — иначе каждая пауза в соединении обнуляет окно, и
#                          скорость приходится набирать заново.
sysctl_file=/etc/sysctl.d/99-noisefloor.conf
log "настраиваю сеть ядра ($sysctl_file)"
modprobe nf_conntrack 2>/dev/null || true
modprobe tcp_bbr 2>/dev/null || true
printf 'nf_conntrack\ntcp_bbr\n' > /etc/modules-load.d/noisefloor.conf 2>/dev/null || true
cat > "$sysctl_file" <<'SYSCTL'
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.core.netdev_max_backlog = 4096
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0

net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_be_liberal = 1
SYSCTL
# Размер хеш-таблицы conntrack — параметр модуля, а не sysctl. Держим его
# в четверть от максимума: иначе длинные цепочки съедают выигрыш.
echo 32768 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
sysctl -q -p "$sysctl_file" 2>/dev/null || warn "часть сетевых настроек ядро не приняло — смотрите sysctl -p $sysctl_file"
if [ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" != "bbr" ]; then
    warn "bbr в этом ядре недоступен — остаётся $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null); каскад будет медленнее"
fi

# --- Режим перехвата для каскада -------------------------------------------
#
# На ядрах младше 6.0 xray не может выставить IP_TRANSPARENT на TCP-слушателе,
# и TPROXY молча дропает весь клиентский TCP: DNS работает, сайты не
# открываются. Поэтому на старом ядре по умолчанию берём redirect — он
# заворачивает в каскад только TCP, зато работает.
kernel_major="$(uname -r | cut -d. -f1)"
if [ -z "$INTERCEPT_MODE" ]; then
    if [ "${kernel_major:-0}" -ge 6 ] 2>/dev/null; then
        INTERCEPT_MODE=tproxy
    else
        INTERCEPT_MODE=redirect
        warn "ядро $(uname -r) не тянет TPROXY для TCP — режим каскада: redirect (UDP пойдёт мимо каскада)"
        warn "полное покрытие вернёт обновление ядра: apt install linux-generic-hwe-22.04 && reboot"
    fi
fi
case "$INTERCEPT_MODE" in
    tproxy|redirect) : ;;
    *) die "режим перехвата бывает только tproxy или redirect, а не '$INTERCEPT_MODE'" ;;
esac

# --- Публичный адрес --------------------------------------------------------
#
# Берём только IPv4. Раньше адрес спрашивали у ifconfig.me без -4, и на
# сервере с IPv6 он отвечал IPv6-адресом: клиентские конфиги и ссылка каскада
# получались с IPv6, которого у клиентов часто нет, а ссылка vless:// с голым
# IPv6 ещё и не разбиралась на панели (ошибка 500 при подключении релея).
#
# Кандидаты: внешний адрес (как нас видит интернет) и IPv4 на интерфейсах.
# Если их несколько и есть терминал — даём выбрать; без терминала (установка
# из CI, через pipe без tty) берём внешний. --public-host отменяет всё это.

is_ipv4() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

is_private_ipv4() {
    case "$1" in
        10.*|192.168.*|127.*|169.254.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    esac
    return 1
}

pick_public_ipv4() {
    local external="" url addr iface n i choice
    local -a addrs=() notes=()

    for url in https://api.ipify.org https://ifconfig.me https://ipv4.icanhazip.com; do
        external="$(curl -4 -fsS --max-time 10 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
        is_ipv4 "$external" && break
        external=""
    done
    if [ -n "$external" ]; then
        addrs+=("$external"); notes+=("внешний — рекомендуется")
    fi

    while read -r iface addr; do
        addr="${addr%/*}"
        is_ipv4 "$addr" || continue
        [ "$addr" = "$external" ] && continue
        addrs+=("$addr")
        if is_private_ipv4 "$addr"; then
            notes+=("на $iface, частный — снаружи недоступен")
        else
            notes+=("на $iface")
        fi
    done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}')

    n=${#addrs[@]}
    [ "$n" -gt 0 ] || return 0

    if [ "$n" -gt 1 ] && { : </dev/tty; } 2>/dev/null; then
        {
            printf '\nНа сервере несколько IPv4-адресов. Нужен ВНЕШНИЙ (публичный) —\n'
            printf 'тот, по которому сервер доступен из интернета. Его получат\n'
            printf 'устройства в конфигах и второй сервер связки; с частным адресом\n'
            printf '(10.x, 172.16–31.x, 192.168.x, 100.64–127.x) никто не подключится.\n'
            if [ -n "$external" ]; then
                printf 'Внешний определён автоматически — это пункт 1, обычно выбирать его.\n\n'
            else
                printf 'Внешний адрес через интернет узнать не удалось — посмотрите его в\n'
                printf 'личном кабинете хостинга (или прервите и укажите --public-host).\n\n'
            fi
            for ((i = 0; i < n; i++)); do
                printf '  %d) %-15s  (%s)\n' "$((i + 1))" "${addrs[$i]}" "${notes[$i]}"
            done
            printf 'Номер [1]: '
        } >/dev/tty
        choice=""
        read -r -t 60 choice </dev/tty || true
        choice="${choice:-1}"
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$n" ]; then
            PUBLIC_HOST="${addrs[$((choice - 1))]}"
            return 0
        fi
        warn "нет такого номера — беру первый"
    fi
    PUBLIC_HOST="${addrs[0]}"
}

if [ -z "$PUBLIC_HOST" ]; then
    pick_public_ipv4
    [ -n "$PUBLIC_HOST" ] && log "публичный адрес (IPv4): $PUBLIC_HOST"
    if [ -n "$PUBLIC_HOST" ] && is_private_ipv4 "$PUBLIC_HOST"; then
        warn "$PUBLIC_HOST — частный адрес, из интернета к нему не подключиться; перезапустите с --public-host ВНЕШНИЙ_IP"
    fi
elif ! is_ipv4 "$PUBLIC_HOST" && [[ "$PUBLIC_HOST" == *:* ]]; then
    warn "--public-host задан как IPv6 ($PUBLIC_HOST) — клиенты без IPv6 не подключатся"
fi
[ -n "$PUBLIC_HOST" ] || warn "не удалось определить публичный адрес — впишите его в панели вручную"

# --- Файлы ------------------------------------------------------------------

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

cat > docker-compose.yml <<EOF
services:
  panel:
    image: $IMAGE
    container_name: $CONTAINER
    restart: unless-stopped
    # Без лимита json-лог растёт бесконечно: панель пишет строку на каждый
    # запрос дашборда, а дашборд опрашивает сервер каждые несколько секунд.
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    network_mode: host
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    env_file:
      - .env
    volumes:
      - ./data:/opt/panel/data
      - ./awg_config:/etc/amnezia/amneziawg
EOF

if [ -f .env ] && [ "$FORCE" -eq 0 ]; then
    log ".env уже есть — оставляю как есть (перезаписать: --force)"
else
    if [ "$NO_BACKUP_PASSPHRASE" -eq 1 ]; then
        BACKUP_PASSPHRASE=""
    elif [ -z "$BACKUP_PASSPHRASE" ]; then
        BACKUP_PASSPHRASE="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24)"
        GENERATED_PASSPHRASE=1
    fi
    umask 077
    cat > .env <<EOF
# Логин администратора. Пустой пароль означает "сгенерировать при первом
# запуске" — он ляжет в data/INITIAL_ADMIN_PASSWORD.txt.
ADMIN_USERNAME=admin
ADMIN_PASSWORD=

# Ключ подписи сессий. Пустой — сгенерируется сам и сохранится в data/.
SECRET_KEY=
ACCESS_TOKEN_EXPIRE_MINUTES=720

AWG_INTERFACE=$AWG_INTERFACE
AWG_CONFIG_DIR=/etc/amnezia/amneziawg
EGRESS_INTERFACE=auto

LIVE_MANAGEMENT_ENABLED=true
AUTO_APPLY_ON_START=true

DEFAULT_SERVER_ADDRESS=$SERVER_ADDRESS
DEFAULT_LISTEN_PORT=$LISTEN_PORT
DEFAULT_DNS=$DNS

# tproxy — TCP и UDP через каскад, требует ядро 6.x+;
# redirect — только TCP, работает везде.
CASCADE_INTERCEPT_MODE=$INTERCEPT_MODE

ISOLATE_CLIENTS=true

# Пустое значение = резервные копии не шифруются, а внутри них приватные
# ключи всех клиентов.
BACKUP_PASSPHRASE=$BACKUP_PASSPHRASE
EOF
    umask 022
fi

# --- Запуск -----------------------------------------------------------------

log "тяну образ"
docker compose pull -q 2>/dev/null || docker compose pull
log "запускаю панель"
docker compose up -d

log "жду, пока панель ответит"
for _ in $(seq 1 60); do
    curl -fsS -o /dev/null "http://127.0.0.1:$PANEL_PORT/" 2>/dev/null && break
    sleep 1
done
curl -fsS -o /dev/null "http://127.0.0.1:$PANEL_PORT/" 2>/dev/null \
    || die "панель не отвечает; смотрите: docker logs $CONTAINER --tail 50"

ADMIN_PASSWORD="$(docker exec "$CONTAINER" sh -c \
    'sed -n "s/^ *Пароль: *//p" /opt/panel/data/INITIAL_ADMIN_PASSWORD.txt' 2>/dev/null | tr -d '\r')"

# --- Настройка через API: публичный адрес и, если попросили, каскад ---------

api() { # api МЕТОД ПУТЬ [ТЕЛО]
    local method="$1" path="$2" body="${3:-}"
    if [ -n "$body" ]; then
        curl -fsS -X "$method" "http://127.0.0.1:$PANEL_PORT$path" \
            -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$body"
    else
        curl -fsS -X "$method" "http://127.0.0.1:$PANEL_PORT$path" \
            -H "Authorization: Bearer $TOKEN"
    fi
}

CONFIGURED_VIA_API=0
if [ -n "$ADMIN_PASSWORD" ]; then
    TOKEN="$(curl -fsS -X POST "http://127.0.0.1:$PANEL_PORT/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null || true)"

    if [ -n "${TOKEN:-}" ]; then
        update='{}'
        [ -n "$PUBLIC_HOST" ] && update="$(python3 -c '
import json,sys
u=json.loads(sys.argv[1]); u["endpoint_host"]=sys.argv[2]; print(json.dumps(u))' "$update" "$PUBLIC_HOST")"
        if [ -n "$RELAY_URL" ] && [ -n "$RELAY_TOKEN" ]; then
            update="$(python3 -c '
import json,sys
u=json.loads(sys.argv[1])
u["cascade_enabled"]=True; u["cascade_sync_url"]=sys.argv[2]; u["cascade_sync_token"]=sys.argv[3]
print(json.dumps(u))' "$update" "$RELAY_URL" "$RELAY_TOKEN")"
        fi
        if [ "$update" != '{}' ] && api PUT /api/server "$update" >/dev/null 2>&1; then
            CONFIGURED_VIA_API=1
            if [ -n "$RELAY_URL" ] && [ -n "$RELAY_TOKEN" ]; then
                log "забираю параметры у релея"
                api POST /api/server/cascade/sync >/dev/null 2>&1 \
                    || warn "релей не ответил — проверьте адрес и токен во вкладке «Сервер»"
            fi
            api POST /api/server/apply >/dev/null 2>&1 || warn "не удалось применить конфиг — нажмите «Применить на сервере» в панели"
        fi
    fi
fi

# --- Команда noisefloor и агент обновлений ----------------------------------
#
# `noisefloor update` на хосте и кнопка «Обновить» в панели — одно и то же
# действие: скачать образ, перезапустить, дождаться здоровья, при неудаче
# вернуть прежнюю версию. Кнопке нужен systemd-юнит, который ждёт запроса
# от панели; ставит его `noisefloor install-agent`.
log "ставлю команду noisefloor"
if curl -fsSL "https://raw.githubusercontent.com/vbif666/noisefloor/master/tools/noisefloor" -o /usr/local/bin/noisefloor.tmp; then
    mv /usr/local/bin/noisefloor.tmp /usr/local/bin/noisefloor
    chmod +x /usr/local/bin/noisefloor
    mkdir -p /etc/noisefloor
    grep -qs "^panel=" /etc/noisefloor/services 2>/dev/null && sed -i "/^panel=/d" /etc/noisefloor/services
    echo "panel=$INSTALL_DIR" >> /etc/noisefloor/services
    noisefloor install-agent >/dev/null 2>&1 \
        || warn "агент обновлений не установился — кнопка в панели работать не будет, остаётся noisefloor update"
else
    warn "не удалось скачать tools/noisefloor — обновлять придётся вручную: docker compose pull && docker compose up -d"
fi

# --- Итог -------------------------------------------------------------------

echo
printf '\033[1;32m=== Панель установлена ===\033[0m\n\n'
printf '  Адрес:     http://%s:%s\n' "${PUBLIC_HOST:-АДРЕС_СЕРВЕРА}" "$PANEL_PORT"
printf '  Логин:     admin\n'
printf '  Пароль:    %s\n' "${ADMIN_PASSWORD:-см. docker exec $CONTAINER cat /opt/panel/data/INITIAL_ADMIN_PASSWORD.txt}"
printf '  Каталог:   %s\n' "$INSTALL_DIR"
printf '  Интерфейс: %s (%s, UDP %s)\n' "$AWG_INTERFACE" "$SERVER_ADDRESS" "$LISTEN_PORT"
printf '  Каскад:    режим перехвата %s\n' "$INTERCEPT_MODE"
if [ "${GENERATED_PASSPHRASE:-0}" -eq 1 ]; then
    printf '\n  Пароль шифрования резервных копий (сохраните, второй раз не покажу):\n    %s\n' "$BACKUP_PASSPHRASE"
fi
echo
if [ "$CONFIGURED_VIA_API" -eq 1 ]; then
    printf '  Публичный адрес уже прописан и конфиг применён.\n'
else
    printf '  Дальше: вкладка «Сервер» → «Публичный адрес сервера» → %s → Сохранить → Применить.\n' "${PUBLIC_HOST:-адрес этого сервера}"
fi
if [ -n "$RELAY_URL" ] && [ "$CONFIGURED_VIA_API" -eq 1 ]; then
    printf '  Каскад через %s включён — проверьте значок каскада на вкладке «Пиры».\n' "$RELAY_URL"
elif [ -z "$RELAY_URL" ]; then
    printf '  Каскад: вкладка «Сервер» → блок «Каскад» → адрес релея и токен с его страницы.\n'
fi
printf '  Устройства: вкладка «Пиры» → «+ Добавить пира» → QR-код в приложение AmneziaWG.\n'
printf '  Обновления: панель сама скажет, когда выйдет новая версия; кнопка «Обновить»\n'
printf '  там же, либо на сервере: noisefloor check / noisefloor update / noisefloor rollback.\n'
echo
printf '\033[1;33m  Панель открыта в интернет по HTTP без шифрования.\033[0m Закройте её фаерволом\n'
printf '  или обратным прокси с сертификатом — см. docs/DEPLOY.md, «Закройте панель от посторонних».\n'
echo
