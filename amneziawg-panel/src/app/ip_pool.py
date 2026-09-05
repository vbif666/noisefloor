"""
Выделение свободного IP-адреса клиенту из подсети сервера.
"""
import ipaddress


def next_available_ip(server_address_cidr: str, used_ips: set[str]) -> str:
    """
    server_address_cidr: адрес сервера в туннеле, напр. '10.13.13.1/24'.
    used_ips: множество уже занятых адресов (без маски), включая адрес сервера.

    Возвращает адрес нового клиента в виде '10.13.13.2/32'.
    """
    iface = ipaddress.ip_interface(server_address_cidr)
    network = iface.network

    for host in network.hosts():
        host_str = str(host)
        if host_str in used_ips:
            continue
        return f"{host_str}/32"

    raise ValueError(
        f"В подсети {network} не осталось свободных адресов — "
        "увеличьте подсеть сервера (например, замените /24 на /22) "
        "или удалите неиспользуемых клиентов."
    )
