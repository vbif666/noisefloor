"""
Сборка конфигурационных файлов в формате awg-quick (тот же INI, что у
wg-quick, плюс поля обфускации AmneziaWG 2.0 в секции [Interface]).

Поля Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5 указываются на КАЖДОЙ стороне
туннеля отдельно, но значения должны быть ОДИНАКОВЫМИ на сервере и на
всех его клиентах — это общая схема маскировки заголовков пакетов, а не
секрет конкретного пира. Поэтому client_config() рендерит эти поля из
ServerConfig, а не из собственных полей Peer.
"""
from __future__ import annotations

from . import cascade
from .config import settings
from .models import Peer, ServerConfig

# Скрипт лежит в образе; он же отвечает за идемпотентность правил.
RULES_SCRIPT = "/usr/local/bin/noisefloor-rules"

_OBFS_INT_FIELDS = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")
_OBFS_STR_FIELDS = ("h1", "h2", "h3", "h4")
_CPS_FIELDS = ("i1", "i2", "i3", "i4", "i5")


def _obfuscation_lines(obj) -> list[str]:
    lines: list[str] = []
    for field in _OBFS_INT_FIELDS:
        lines.append(f"{field.capitalize()} = {getattr(obj, field)}")
    for field in _OBFS_STR_FIELDS:
        value = getattr(obj, field)
        if value:
            lines.append(f"{field.upper()} = {value}")
    for field in _CPS_FIELDS:
        value = getattr(obj, field)
        if value:
            lines.append(f"{field.upper()} = {value}")
    return lines


def server_interface_block(server: ServerConfig) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {server.private_key}",
        f"Address = {server.address}",
        f"ListenPort = {server.listen_port}",
    ]
    if server.mtu:
        lines.append(f"MTU = {server.mtu}")
    lines.extend(_obfuscation_lines(server))
    if server.egress_interface:
        # Раньше здесь собиралась цепочка из шести iptables-команд через
        # точку с запятой, а PostDown удалял их по одной. При жёсткой
        # остановке контейнера PostDown не отрабатывал, и правила
        # накапливались — на проде их набралось по семь копий.
        #
        # Теперь вся работа у noisefloor-rules: он держит правила в
        # собственных цепочках и очищает их перед заполнением, поэтому
        # повторный запуск не может ничего продублировать.
        mode = settings.cascade_intercept_mode if server.cascade_enabled else "off"
        up = [
            RULES_SCRIPT, "up",
            "--iface", server.interface_name,
            "--egress", server.egress_interface,
            "--mode", mode,
        ]
        if server.cascade_enabled:
            up += ["--cascade-port", str(cascade.REDIRECT_PORT)]
        if settings.isolate_clients:
            up.append("--isolate-clients")
        down = [
            RULES_SCRIPT, "down",
            "--iface", server.interface_name,
            "--egress", server.egress_interface,
        ]
        lines.append("PostUp = " + " ".join(up))
        lines.append("PostDown = " + " ".join(down))
    return "\n".join(lines)


def server_peer_block(peer: Peer) -> str:
    lines = [
        "[Peer]",
        f"# {peer.name}",
        f"PublicKey = {peer.public_key}",
        f"PresharedKey = {peer.preshared_key}",
        f"AllowedIPs = {peer.address}",
    ]
    return "\n".join(lines)


def full_server_config(server: ServerConfig, peers: list[Peer]) -> str:
    """Полный awg0.conf сервера: интерфейс + один [Peer] блок на каждого включённого клиента."""
    blocks = [server_interface_block(server)]
    for peer in peers:
        if peer.enabled:
            blocks.append(server_peer_block(peer))
    return "\n\n".join(blocks) + "\n"


def client_config(peer: Peer, server: ServerConfig) -> str:
    """Конфиг, который клиент импортирует в приложение AmneziaWG / сканирует как QR."""
    lines = [
        "[Interface]",
        f"PrivateKey = {peer.private_key}",
        f"Address = {peer.address}",
    ]
    # Явный MTU (тот же, что на сервере) вместо автоопределения клиентом:
    # без него часть клиентов сама угадывает MTU по своему аплинку и на
    # сетях с меньшим реальным path MTU (мобильные операторы, двойной VPN)
    # получает PMTU black hole — см. комментарий про TCPMSS в
    # server_interface_block.
    if server.mtu:
        lines.append(f"MTU = {server.mtu}")
    dns = peer.dns_override or server.dns
    if dns:
        lines.append(f"DNS = {dns}")
    # Jc/Jmin/Jmax/S1-S4/H1-H4 — параметры интерфейса, а не секрет пира: они
    # обязаны совпадать с тем, что настроено на сервере, иначе сервер не
    # опознает пакеты этого клиента как WireGuard-трафик.
    lines.extend(_obfuscation_lines(server))
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server.public_key}")
    lines.append(f"PresharedKey = {peer.preshared_key}")
    endpoint_host = server.endpoint_host or "YOUR_SERVER_HOST_OR_IP"
    lines.append(f"Endpoint = {endpoint_host}:{server.listen_port}")
    lines.append(f"AllowedIPs = {peer.allowed_ips_client}")
    if peer.persistent_keepalive:
        lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
    return "\n".join(lines) + "\n"


def strippable_server_config(server: ServerConfig, peers: list[Peer]) -> str:
    """
    То же самое, что full_server_config — awg-quick strip сам уберёт
    Address/MTU/PostUp/PostDown при подготовке к `awg syncconf`.
    Отдельная функция оставлена для ясности вызывающего кода.
    """
    return full_server_config(server, peers)
