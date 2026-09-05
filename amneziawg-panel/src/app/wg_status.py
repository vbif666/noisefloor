"""
Разбор вывода `awg show <iface> dump` (формат идентичен `wg show ... dump`):

Первая строка:  private-key  public-key  listen-port  fwmark
Далее, по одной строке на пира:
    public-key  preshared-key  endpoint  allowed-ips  latest-handshake  transfer-rx  transfer-tx  persistent-keepalive

Поля разделены табуляцией. Отсутствующие значения передаются как "(none)"/"0".
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PeerStatus:
    public_key: str
    endpoint: str | None
    allowed_ips: str
    latest_handshake: int  # unix timestamp, 0 = ещё не было
    transfer_rx: int
    transfer_tx: int
    persistent_keepalive: str


@dataclass
class InterfaceStatus:
    listen_port: int
    peers: dict[str, PeerStatus]  # public_key -> status


def parse_dump(raw: str) -> InterfaceStatus | None:
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return None

    header = lines[0].split("\t")
    try:
        listen_port = int(header[2])
    except (IndexError, ValueError):
        listen_port = 0

    peers: dict[str, PeerStatus] = {}
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        pub_key, _psk, endpoint, allowed_ips, handshake, rx, tx, keepalive = fields[:8]
        peers[pub_key] = PeerStatus(
            public_key=pub_key,
            endpoint=None if endpoint == "(none)" else endpoint,
            allowed_ips=allowed_ips,
            latest_handshake=int(handshake) if handshake.isdigit() else 0,
            transfer_rx=int(rx) if rx.isdigit() else 0,
            transfer_tx=int(tx) if tx.isdigit() else 0,
            persistent_keepalive=keepalive,
        )
    return InterfaceStatus(listen_port=listen_port, peers=peers)
