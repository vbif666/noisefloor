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

import hashlib
import ipaddress
import shutil
from pathlib import Path

from . import cascade
from .config import settings
from .models import PROTOCOL_AWG1, PROTOCOL_AWG2, PROTOCOL_AWG20, Peer, ServerConfig, Tunnel
from .obfuscation import AWG31_PARAMS

# Скрипт лежит в образе; он же отвечает за идемпотентность правил.
RULES_SCRIPT = "/usr/local/bin/noisefloor-rules"

_OBFS_INT_FIELDS = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")
_OBFS_STR_FIELDS = ("h1", "h2", "h3", "h4")
_CPS_FIELDS = ("i1", "i2", "i3", "i4", "i5")


# Самый длинный пакет данных AmneziaWG 3.1 в UDP: S4 + заголовок 16 + содержимое
# + тег 16 (amneziawg-go v3.1.20260828, device/send.go). Больше ничего не растит
# максимум: I1-I5 уходят только перед рукопожатием, а ContentPaddingAddition и
# RandomTrailers ограничены peer.udpWindow, то есть самым длинным пакетом,
# который пир уже видел. Запас соответствует плану и почти закрывает разницу с
# внешним IPv6 (20 байт).
_LINK_MTU = 1500
_IPV4_HEADER = 20
_UDP_HEADER = 8
_WG_DATA_OVERHEAD = 32
_MTU_MARGIN = 16


def profile_mtu(s4: int | None) -> int:
    """MTU, при котором полноразмерный пакет не фрагментируется. Значение
    awg-quick по умолчанию (1420) при S4 больше 20 выходит за 1500 байт."""
    return _LINK_MTU - _IPV4_HEADER - _UDP_HEADER - _WG_DATA_OVERHEAD - _MTU_MARGIN - (s4 or 0)


def effective_mtu(server) -> int:
    """Явный MTU или рассчитанный из профиля основного интерфейса."""
    return server.mtu or profile_mtu(getattr(server, "s4", None))


def tunnel_mtu(server, tunnel) -> int | None:
    """MTU дополнительного интерфейса. У AmneziaWG 2.0 свой S4, остальным хватает
    значения awg-quick по умолчанию."""
    s4 = getattr(tunnel, "s4", None)
    return server.mtu or (profile_mtu(s4) if s4 else None)


_PROC_IPV6 = Path("/proc/sys/net/ipv6/conf")
_IPV6_MIN_MTU = 1280


def ipv6_ready(server) -> bool:
    """Можно ли выдавать адреса ULA. Если нет, конфиги остаются только с IPv4:
    awg-quick снимает интерфейс, когда адрес IPv6 не добавляется."""
    if not settings.client_ipv6_reject or effective_mtu(server) < _IPV6_MIN_MTU:
        return False
    if shutil.which("ip6tables") is None:
        return False
    try:
        return all(
            (_PROC_IPV6 / scope / "disable_ipv6").read_text().strip() == "0"
            for scope in ("all", "default")
        )
    except OSError:
        return False


def ula_prefix(server) -> int:
    """Префикс fdXX:XXXX:XXXX::/64. Выводится из ключа сервера, поэтому один раз
    и без миграции БД. Сменился ключ - клиенты всё равно получают новые конфиги."""
    digest = hashlib.sha256(b"noisefloor-ula:" + server.private_key.encode()).digest()
    return int.from_bytes(b"\xfd" + digest[:5] + bytes(10), "big")


def with_ipv6(address: str, server) -> str:
    """IPv4-адрес с парным ULA: младшие 32 бита равны IPv4, а длина префикса
    повторяет его. 10.13.13.1/24 -> fdXX::a0d:d01/120, клиентский /32 -> /128."""
    if not ipv6_ready(server):
        return address
    try:
        interface = ipaddress.IPv4Interface(address)
    except ValueError:
        return address
    pair = ipaddress.IPv6Address(ula_prefix(server) | int(interface.ip))
    return f"{address}, {pair}/{96 + interface.network.prefixlen}"


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
    # AmneziaWG 3.1: ключ защиты заголовков и тайминги. Без ключа интерфейс
    # остаётся 2.0 — клиент 3.1 к нему не подключится, и наоборот.
    hpk = getattr(obj, "header_protection_key", "")
    if hpk:
        lines.append(f"HeaderProtectionKey = {hpk}")
        for key, value in AWG31_PARAMS:
            lines.append(f"{key} = {value}")
    return lines


def _peer_protocol(peer) -> str:
    return getattr(peer, "protocol", None) or PROTOCOL_AWG2


def _awg1_obfuscation_lines(tunnel) -> list[str]:
    """AmneziaWG 1.x понимает только Jc/Jmin/Jmax, S1/S2 и H1–H4. Поля 2.0
    (S3/S4, I1–I5) в его конфиг не пишем: старый клиент их не разберёт."""
    lines = [
        f"Jc = {tunnel.jc}",
        f"Jmin = {tunnel.jmin}",
        f"Jmax = {tunnel.jmax}",
        f"S1 = {tunnel.s1}",
        f"S2 = {tunnel.s2}",
    ]
    for field in _OBFS_STR_FIELDS:
        value = getattr(tunnel, field)
        if value:
            lines.append(f"{field.upper()} = {value}")
    return lines


def _awg20_obfuscation_lines(tunnel) -> list[str]:
    """Отдельный интерфейс AmneziaWG 2.0: S1–S4 и H1–H4 без ключа защиты
    заголовков и параметров 3.1 — клиент 2.0 их не знает."""
    lines = [
        f"Jc = {tunnel.jc}",
        f"Jmin = {tunnel.jmin}",
        f"Jmax = {tunnel.jmax}",
        f"S1 = {tunnel.s1}",
        f"S2 = {tunnel.s2}",
        f"S3 = {tunnel.s3}",
        f"S4 = {tunnel.s4}",
    ]
    for field in _OBFS_STR_FIELDS:
        value = getattr(tunnel, field)
        if value:
            lines.append(f"{field.upper()} = {value}")
    return lines


def _tunnel_obfuscation_lines(tunnel) -> list[str]:
    if tunnel.protocol == PROTOCOL_AWG20:
        return _awg20_obfuscation_lines(tunnel)
    if tunnel.protocol == PROTOCOL_AWG1:
        return _awg1_obfuscation_lines(tunnel)
    return []


def rules_commands(server: ServerConfig, interfaces: list[str]) -> tuple[list[str], list[str]]:
    """Команды noisefloor-rules up/down для всех интерфейсов туннеля разом.

    Цепочки у скрипта общие и перед заполнением очищаются, поэтому правила
    для всех протоколов ставятся одним вызовом из PostUp основного
    интерфейса. Дополнительные интерфейсы своих PostUp не имеют: иначе
    каждый их подъём стирал бы правила соседей."""
    iface_args: list[str] = []
    for name in interfaces:
        iface_args += ["--iface", name]
    intercept = server.cascade_enabled and not cascade.intercept_suspended(server)
    mode = cascade.intercept_mode() if intercept else "off"
    up = [
        RULES_SCRIPT, "up",
        *iface_args,
        "--egress", server.egress_interface,
        "--mode", mode,
    ]
    if intercept:
        up += ["--cascade-port", str(cascade.REDIRECT_PORT)]
        if cascade.dns_via_cascade():
            up += ["--cascade-dns-port", str(cascade.DNS_REDIRECT_PORT)]
        # QUIC режем в обоих режимах: в redirect он ушёл бы мимо каскада
        # с настоящим адресом сервера, в tproxy — поехал бы поверх
        # TCP-туннеля до релея и тормозил бы страницы сильнее, чем TCP.
        if settings.cascade_block_quic:
            up.append("--block-quic")
    if settings.isolate_clients:
        up.append("--isolate-clients")
    if ipv6_ready(server):
        up.append("--ipv6-reject")
    down = [
        RULES_SCRIPT, "down",
        *iface_args,
        "--egress", server.egress_interface,
    ]
    return up, down


def server_interface_block(server: ServerConfig, extra_interfaces: list[str] | tuple[str, ...] = ()) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {server.private_key}",
        f"Address = {with_ipv6(server.address, server)}",
        f"ListenPort = {server.listen_port}",
        f"MTU = {effective_mtu(server)}",
    ]
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
        #
        # "|| true": ненулевой код PostUp заставил бы awg-quick снять только
        # что поднятый интерфейс, и из-за одного правила VPN пропал бы целиком.
        # Сбой не теряется: сразу за подъёмом config_sync.ensure_rules сам
        # сверяет правила, получает ошибку и показывает её в статусе.
        up, down = rules_commands(server, [server.interface_name, *extra_interfaces])
        lines.append("PostUp = " + " ".join(up) + " || true")
        lines.append("PostDown = " + " ".join(down))
    return "\n".join(lines)


def server_peer_block(peer: Peer, server: ServerConfig) -> str:
    lines = [
        "[Peer]",
        f"# {peer.name}",
        f"PublicKey = {peer.public_key}",
        f"PresharedKey = {peer.preshared_key}",
        f"AllowedIPs = {with_ipv6(peer.address, server)}",
    ]
    return "\n".join(lines)


def full_server_config(
    server: ServerConfig, peers: list[Peer], extra_interfaces: list[str] | tuple[str, ...] = ()
) -> str:
    """Полный awg0.conf сервера: интерфейс + один [Peer] блок на каждого
    включённого клиента AmneziaWG 2.0. extra_interfaces — включённые
    дополнительные интерфейсы: правила фаервола ставятся и для них."""
    blocks = [server_interface_block(server, extra_interfaces)]
    for peer in peers:
        if peer.enabled and _peer_protocol(peer) == PROTOCOL_AWG2:
            blocks.append(server_peer_block(peer, server))
    return "\n\n".join(blocks) + "\n"


def tunnel_config(tunnel: Tunnel, server: ServerConfig, peers: list[Peer]) -> str:
    """Конфиг дополнительного интерфейса (AWG 2.0, AWG 1.x или обычный WireGuard).

    Без PostUp/PostDown: правила для него ставит основной интерфейс
    (см. rules_commands). MTU общий с основным — клиенты в тех же сетях."""
    lines = [
        "[Interface]",
        f"PrivateKey = {tunnel.private_key}",
        f"Address = {with_ipv6(tunnel.address, server)}",
        f"ListenPort = {tunnel.listen_port}",
    ]
    mtu = tunnel_mtu(server, tunnel)
    if mtu:
        lines.append(f"MTU = {mtu}")
    lines.extend(_tunnel_obfuscation_lines(tunnel))
    blocks = ["\n".join(lines)]
    for peer in peers:
        if peer.enabled and _peer_protocol(peer) == tunnel.protocol:
            blocks.append(server_peer_block(peer, server))
    return "\n\n".join(blocks) + "\n"


def client_config(peer: Peer, server: ServerConfig, tunnel: Tunnel | None = None) -> str:
    """Конфиг, который клиент импортирует в приложение AmneziaWG / сканирует как QR.

    tunnel — дополнительный интерфейс, к которому относится клиент (AWG 2.0,
    AWG 1.x или обычный WireGuard); None — основной интерфейс AmneziaWG 3.1."""
    lines = [
        "[Interface]",
        f"PrivateKey = {peer.private_key}",
        f"Address = {with_ipv6(peer.address, server)}",
    ]
    # Явный MTU (тот же, что на сервере) вместо автоопределения клиентом:
    # без него часть клиентов сама угадывает MTU по своему аплинку и на
    # сетях с меньшим реальным path MTU (мобильные операторы, двойной VPN)
    # получает PMTU black hole — см. комментарий про TCPMSS в
    # server_interface_block.
    mtu = tunnel_mtu(server, tunnel) if tunnel else effective_mtu(server)
    if mtu:
        lines.append(f"MTU = {mtu}")
    dns = peer.dns_override or server.dns
    if dns:
        lines.append(f"DNS = {dns}")
    # Jc/Jmin/Jmax/S1-S4/H1-H4 — параметры интерфейса, а не секрет пира: они
    # обязаны совпадать с тем, что настроено на сервере, иначе сервер не
    # опознает пакеты этого клиента как WireGuard-трафик. У обычного
    # WireGuard их нет вовсе — стандартное приложение не примет такие поля.
    if tunnel is None:
        lines.extend(_obfuscation_lines(server))
    else:
        lines.extend(_tunnel_obfuscation_lines(tunnel))
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {(tunnel or server).public_key}")
    lines.append(f"PresharedKey = {peer.preshared_key}")
    endpoint_host = server.endpoint_host or "YOUR_SERVER_HOST_OR_IP"
    if ":" in endpoint_host and not endpoint_host.startswith("["):
        endpoint_host = f"[{endpoint_host}]"  # IPv6 в Endpoint — только в скобках
    lines.append(f"Endpoint = {endpoint_host}:{(tunnel or server).listen_port}")
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
