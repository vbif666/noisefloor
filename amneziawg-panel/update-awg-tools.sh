#!/bin/sh
# Периодическая проверка и обновление бинарников AmneziaWG внутри контейнера:
# amneziawg-go (userspace-ядро) + awg / awg-quick (amneziawg-tools).
#
# Источник - ТОЛЬКО официальные репозитории amnezia-vpn (не форк kaskad-pro):
#   https://github.com/amnezia-vpn/amneziawg-go
#   https://github.com/amnezia-vpn/amneziawg-tools
# У amneziawg-go нет готовых бинарных релизов - только git-теги, поэтому
# обновление всегда собирает свежий тег из исходников (git clone + make),
# используя git/go/build-essential, которые остаются в образе для этого.
#
# Использование:
#   update-awg-tools.sh          # одна проверка и выход (exit 0, даже если апдейта не было)
#   update-awg-tools.sh --loop   # бесконечный цикл, пауза AWG_AUTO_UPDATE_INTERVAL_HOURS часов

set -u

REPO_GO="amnezia-vpn/amneziawg-go"
REPO_TOOLS="amnezia-vpn/amneziawg-tools"
INTERVAL_HOURS="${AWG_AUTO_UPDATE_INTERVAL_HOURS:-24}"
# Оба репозитория публичные, токен не обязателен. Он полезен только чтобы не
# упереться в лимит GitHub API без авторизации (60 запросов/час на IP).
GITHUB_PAT="${AWG_UPDATE_GITHUB_PAT:-}"
BIN_DIR="/usr/local/bin"
BACKUP_DIR="/opt/panel/data/bin-backup"
VERSION_FILE="/opt/panel/data/awg-versions.txt"
KEEP_BACKUPS=5

log() { echo "[awg-update] $*"; }

gh_curl() {
    if [ -n "$GITHUB_PAT" ]; then
        curl -fsSL --max-time 30 -H "Authorization: token $GITHUB_PAT" "$@"
    else
        curl -fsSL --max-time 30 "$@"
    fi
}

# latest_tag <owner/repo> - самый свежий git-тег (GitHub отдаёт их
# в порядке от новых к старым)
latest_tag() {
    gh_curl "https://api.github.com/repos/$1/tags?per_page=1" 2>/dev/null \
        | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
    print(data[0]["name"] if data else "")
except Exception:
    pass
' 2>/dev/null
}

# installed_version <name> <built-in-env-fallback>
installed_version() {
    v="$(grep -m1 "^$1=" "$VERSION_FILE" 2>/dev/null | cut -d= -f2-)"
    [ -n "$v" ] && echo "$v" || echo "$2"
}

save_version() {
    name="$1"; ver="$2"
    mkdir -p "$(dirname "$VERSION_FILE")"
    tmpf="$(mktemp)"
    { [ -f "$VERSION_FILE" ] && grep -v "^$name=" "$VERSION_FILE"; printf '%s=%s\n' "$name" "$ver"; } > "$tmpf" 2>/dev/null
    mv "$tmpf" "$VERSION_FILE"
}

build_amneziawg_go() {
    tag="$1"; workdir="$2"
    git clone --quiet --depth 1 --branch "$tag" "https://github.com/$REPO_GO" "$workdir" 2>&1 | sed 's/^/[git] /' \
        && (cd "$workdir" && make) 2>&1 | sed 's/^/[make] /' \
        && [ -x "$workdir/amneziawg-go" ]
}

build_amneziawg_tools() {
    tag="$1"; workdir="$2"
    git clone --quiet --depth 1 --branch "$tag" "https://github.com/$REPO_TOOLS" "$workdir" 2>&1 | sed 's/^/[git] /' \
        && (cd "$workdir/src" && make) 2>&1 | sed 's/^/[make] /' \
        && [ -x "$workdir/src/wg" ] && [ -f "$workdir/src/wg-quick/linux.bash" ]
}

check_and_update() {
    go_tag="$(latest_tag "$REPO_GO")"
    tools_tag="$(latest_tag "$REPO_TOOLS")"
    changed=0
    ts="$(date +%Y%m%d_%H%M%S)"
    tmpdir="$(mktemp -d)"

    if [ -z "$go_tag" ] && [ -z "$tools_tag" ]; then
        log "не удалось узнать актуальные версии через GitHub API (rate-limit? нет сети?) - пропуск проверки"
        rm -rf "$tmpdir"
        return 1
    fi

    cur_go="$(installed_version amneziawg-go "${AWG_GO_BUILT_REF:-}")"
    if [ -n "$go_tag" ] && [ "$go_tag" != "$cur_go" ]; then
        log "amneziawg-go: $cur_go -> $go_tag, собираю из $REPO_GO..."
        if build_amneziawg_go "$go_tag" "$tmpdir/go"; then
            mkdir -p "$BACKUP_DIR/$ts"
            [ -f "$BIN_DIR/amneziawg-go" ] && cp "$BIN_DIR/amneziawg-go" "$BACKUP_DIR/$ts/amneziawg-go"
            cp "$tmpdir/go/amneziawg-go" "$BIN_DIR/amneziawg-go" && chmod +x "$BIN_DIR/amneziawg-go"
            save_version amneziawg-go "$go_tag"
            changed=1
            log "amneziawg-go обновлён до $go_tag"
        else
            log "не удалось собрать amneziawg-go $go_tag - оставляю текущую версию ($cur_go)"
        fi
    fi

    cur_tools="$(installed_version amneziawg-tools "${AWG_TOOLS_BUILT_REF:-}")"
    if [ -n "$tools_tag" ] && [ "$tools_tag" != "$cur_tools" ]; then
        log "amneziawg-tools: $cur_tools -> $tools_tag, собираю из $REPO_TOOLS..."
        if build_amneziawg_tools "$tools_tag" "$tmpdir/tools"; then
            mkdir -p "$BACKUP_DIR/$ts"
            [ -f "$BIN_DIR/awg" ] && cp "$BIN_DIR/awg" "$BACKUP_DIR/$ts/awg"
            [ -f "$BIN_DIR/awg-quick" ] && cp "$BIN_DIR/awg-quick" "$BACKUP_DIR/$ts/awg-quick"
            cp "$tmpdir/tools/src/wg" "$BIN_DIR/awg" && chmod +x "$BIN_DIR/awg"
            cp "$tmpdir/tools/src/wg-quick/linux.bash" "$BIN_DIR/awg-quick" && chmod +x "$BIN_DIR/awg-quick"
            save_version amneziawg-tools "$tools_tag"
            changed=1
            log "amneziawg-tools обновлён до $tools_tag"
        else
            log "не удалось собрать amneziawg-tools $tools_tag - оставляю текущую версию ($cur_tools)"
        fi
    fi

    rm -rf "$tmpdir"

    if [ "$changed" -eq 1 ]; then
        log "бинарники изменились - переприменяю конфиг (down/up ${AWG_INTERFACE:-awg0})"
        if (cd /opt/panel && python3 manage.py restart-interface); then
            log "интерфейс переприменён успешно"
        else
            log "не удалось автоматически переприменить конфиг - перезапустите интерфейс вручную из панели"
        fi
        # оставляем только последние KEEP_BACKUPS бэкапов
        ls -1dt "$BACKUP_DIR"/*/ 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -rf
    else
        log "бинарники уже актуальны (amneziawg-go=$cur_go, amneziawg-tools=$cur_tools)"
    fi
    return 0
}

if [ "${1:-}" = "--loop" ]; then
    log "фоновый цикл запущен: проверка каждые ${INTERVAL_HOURS}ч, источники $REPO_GO + $REPO_TOOLS"
    while true; do
        check_and_update
        sleep "$((INTERVAL_HOURS * 3600))"
    done
else
    check_and_update
fi
