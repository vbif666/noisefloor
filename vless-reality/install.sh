#!/usr/bin/env bash
#
# Установка релея NOISEFLOOR (VLESS + REALITY) на чистый Ubuntu/Debian.
#
# Это сервер 2 связки — выходной узел, чьим адресом клиенты видны в интернете.
# Сервер 1 — панель, точка входа, к которой подключаются устройства; она
# ставится скриптом amneziawg-panel/install.sh и нужна в любом случае.
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

  --public-host АДРЕС   IP или домен этого сервера (по умолчанию IPv4, при нескольких — спросит)
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

# --- Сетевые настройки ядра -------------------------------------------------
#
# Пишем одним файлом в sysctl.d: свой файл переживёт обновление системы, и
# всё, что мы трогаем, видно в одном месте.
#
# Зачем каждая строка:
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

# --- Команда noisefloor и агент обновлений ----------------------------------
#
# `noisefloor update` на хосте и кнопка «Обновить» в панели — одно и то же
# действие: скачать образ, перезапустить, дождаться здоровья, при неудаче
# вернуть прежнюю версию. Кнопке нужен systemd-юнит, который ждёт запроса
# от релея (тот же агент обслуживает и панель); ставит его `noisefloor install-agent`.
log "ставлю команду noisefloor"
if curl -fsSL "https://raw.githubusercontent.com/vbif666/noisefloor/master/tools/noisefloor" -o /usr/local/bin/noisefloor.tmp; then
    mv /usr/local/bin/noisefloor.tmp /usr/local/bin/noisefloor
    chmod +x /usr/local/bin/noisefloor
    mkdir -p /etc/noisefloor
    grep -qs "^relay=" /etc/noisefloor/services 2>/dev/null && sed -i "/^relay=/d" /etc/noisefloor/services
    echo "relay=$INSTALL_DIR" >> /etc/noisefloor/services
    noisefloor install-agent >/dev/null 2>&1 \
        || warn "агент обновлений не установился — кнопка «Обновить» на странице релея работать не будет, остаётся noisefloor update"
else
    warn "не удалось скачать tools/noisefloor — обновлять придётся вручную: docker compose pull && docker compose up -d"
fi

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
    printf '  Осталось связать узлы: вернитесь на сервер 1 (панель) и запустите\n'
    printf '  её установщик ещё раз, теперь с этими параметрами:\n'
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
printf '  Обновления: noisefloor check / noisefloor update / noisefloor rollback на этом сервере.\n'
echo
