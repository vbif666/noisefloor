#!/bin/sh
set -e

mkdir -p /opt/panel/data /etc/amnezia/amneziawg

# В части окружений (особенно с network_mode: host) /dev/net/tun уже есть
# с хоста. Если его нет - создаём вручную, иначе userspace-реализация
# (amneziawg-go) не сможет поднять интерфейс.
if [ ! -e /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    chmod 600 /dev/net/tun 2>/dev/null || true
fi

# Автоопределение внешнего интерфейса для NAT/MASQUERADE, если пользователь
# не указал конкретное имя (или явно поставил "auto"). Работает корректно
# только при network_mode: host - там "внешний маршрут контейнера" это и
# есть внешний маршрут хоста. В bridge-режиме отсюда получится eth0
# контейнера (тоже валидно, но это НЕ настоящая внешняя карта хоста).
if [ -z "$EGRESS_INTERFACE" ] || [ "$EGRESS_INTERFACE" = "auto" ]; then
    detected="$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)"
    if [ -n "$detected" ]; then
        export EGRESS_INTERFACE="$detected"
        echo "[entrypoint] EGRESS_INTERFACE не задан - автоопределён как '$detected'"
    else
        export EGRESS_INTERFACE="eth0"
        echo "[entrypoint] Не удалось автоопределить внешний интерфейс, fallback на 'eth0'"
    fi
fi

# Пытаемся включить форвардинг пакетов - без него MASQUERADE не работает.
# Это best-effort: при network_mode: host обычно срабатывает (общий netns
# с хостом), при обычном bridge - как правило нет прав, тогда нужно сделать
# это на хосте вручную (см. README). Ошибку не считаем фатальной.
if [ -w /proc/sys/net/ipv4/ip_forward ]; then
    current="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
    if [ "$current" != "1" ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null \
            && echo "[entrypoint] net.ipv4.ip_forward=1 включён" \
            || echo "[entrypoint] не удалось включить ip_forward изнутри контейнера - включите на хосте вручную"
    fi
else
    echo "[entrypoint] /proc/sys/net/ipv4/ip_forward недоступен на запись - включите ip_forward на хосте вручную"
fi

echo "[entrypoint] AWG_INTERFACE=${AWG_INTERFACE:-awg0} AWG_CONFIG_DIR=${AWG_CONFIG_DIR:-/etc/amnezia/amneziawg} EGRESS_INTERFACE=${EGRESS_INTERFACE}"
echo "[entrypoint] версии: amneziawg-go=${AWG_GO_BUILT_REF:-?} amneziawg-tools=${AWG_TOOLS_BUILT_REF:-?} xray=${XRAY_BUILT_REF:-?}"
if [ -e /sys/module/amneziawg ]; then
    echo "[entrypoint] kernel-модуль amneziawg виден в контейнере - будет использован он (network_mode: host)."
else
    echo "[entrypoint] kernel-модуль amneziawg не виден - awg-quick упадёт в userspace (amneziawg-go)."
fi

# Сборки бинарников в рантайме здесь намеренно нет.
#
# Раньше отсюда фоном запускался update-awg-tools.sh: раз в сутки он тянул
# самый свежий git-тег (не релиз, без подписи и контрольной суммы), собирал
# его из исходников прямо в проде и сам передёргивал сетевой интерфейс - то
# есть устраивал незапланированный обрыв связи в случайный момент, а заодно
# требовал держать в образе go, git и компилятор.
#
# Теперь версии закреплены в Dockerfile, а обновление выглядит так:
#     docker compose pull && docker compose up -d
# Панель по-прежнему СМОТРИТ, не вышло ли новых версий (только запрос к
# GitHub API, без сборки), и показывает это в интерфейсе.

exec "$@"
