#!/bin/sh
# Собирает jail.d/50-noisefloor.local из окружения и запускает fail2ban.
#
# Журнал хоста приезжает томами: /var/log → /host/log, /run/log/journal →
# /host/run/log/journal (см. docker-compose.yml). Откуда читать sshd,
# решает SSH_LOG:
#   auto     — /host/log/auth.log, если он есть и не пустой (Ubuntu с
#              rsyslog), иначе журнал systemd (Debian 12+ без rsyslog);
#   journal  — всегда журнал systemd;
#   ПУТЬ     — этот файл.
set -eu

SSH_PORT="${SSH_PORT:-22}"
SSH_LOG="${SSH_LOG:-auto}"
BANTIME="${BANTIME:-1h}"
FINDTIME="${FINDTIME:-10m}"
MAXRETRY="${MAXRETRY:-5}"
# Свои адреса — через пробел. Сеть клиентов VPN (10.13.0.0/16) в исключениях
# всегда: с неё заходят по SSH через туннель.
IGNOREIP="127.0.0.1/8 ::1 10.13.0.0/16 ${IGNOREIP:-}"

log() { printf '[entrypoint] %s\n' "$*"; }
die() { printf '[entrypoint] ОШИБКА: %s\n' "$*" >&2; exit 1; }

journal_dirs() {
    for d in /host/log/journal /host/run/log/journal; do
        [ -n "$(ls -A "$d" 2>/dev/null)" ] && printf '%s\n' "$d"
    done
    return 0
}

case "$SSH_LOG" in
    auto)
        if [ -s /host/log/auth.log ]; then
            source_kind=file; source_path=/host/log/auth.log
        else
            source_kind=journal
        fi ;;
    journal) source_kind=journal ;;
    *)       source_kind=file; source_path="$SSH_LOG" ;;
esac

if [ "$source_kind" = file ]; then
    [ -e "$source_path" ] || die "нет файла $source_path — проверьте том /var/log:/host/log или SSH_LOG"
    backend="backend = auto
logpath = $source_path"
    log "sshd: файл $source_path"
else
    dir=$(journal_dirs | head -1)
    [ -n "$dir" ] || die "журнала systemd не видно ни в /host/log/journal, ни в /host/run/log/journal, и нет /host/log/auth.log"
    # journalmatch — из filter.d/sshd.local: юниты ssh/sshd, процессы sshd
    # и sshd-session.
    backend="backend = systemd[journalpath=$dir]"
    log "sshd: журнал systemd в $dir"
fi

mkdir -p /etc/fail2ban/jail.d /run/fail2ban
cat > /etc/fail2ban/jail.d/50-noisefloor.local <<EOF
# Сгенерировано entrypoint.sh при старте контейнера — правки здесь пропадут.
[DEFAULT]
ignoreip = $IGNOREIP
bantime  = $BANTIME
findtime = $FINDTIME
maxretry = $MAXRETRY

[sshd]
port = $SSH_PORT
$backend
EOF

log "fail2ban ${NOISEFLOOR_VERSION:-dev}: порт $SSH_PORT, $MAXRETRY попыток за $FINDTIME → бан $BANTIME (повторно — дольше)"

# Остатки от прошлого запуска мешают старту («fail2ban.sock exists»).
rm -f /run/fail2ban/fail2ban.sock /run/fail2ban/fail2ban.pid
exec fail2ban-server -f -x start
