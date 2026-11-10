"""Запуск uvicorn по HTTPS с продлением сертификата на лету.

    python -m app.tls_serve (в релее: python -m tls_serve) МОДУЛЬ:APP ХОСТ ПОРТ КАТАЛОГ_TLS

Перед стартом и потом раз в TLS_CHECK_SECONDS (по умолчанию 6 часов) вызывает
tls-cert: тот перевыпускает сертификат, когда до конца срока осталось меньше
TLS_RENEW_DAYS. Новый сертификат подгружается в уже работающий SSL-контекст -
процесс не перезапускается, поэтому VPN и xray ничего не замечают, а новые
HTTPS-соединения сразу получают свежий сертификат.

Этот файл одинаковый в amneziawg-panel и vless-reality - правьте оба.
"""
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import uvicorn

TLS_CERT_SCRIPT = os.environ.get("TLS_CERT_SCRIPT", "/usr/local/bin/tls-cert")
CHECK_SECONDS = max(60, int(os.environ.get("TLS_CHECK_SECONDS", str(6 * 3600))))


def _log(message: str) -> None:
    print(f"[tls] {message}", flush=True)


def ensure_cert(tls_dir: str) -> None:
    """Выпускает или перевыпускает сертификат, если пора. Ошибку не скрывает."""
    result = subprocess.run(
        ["sh", TLS_CERT_SCRIPT, tls_dir],
        capture_output=True, text=True, timeout=60,
    )
    for line in (result.stdout + result.stderr).splitlines():
        if line.strip():
            print(line, flush=True)
    if result.returncode != 0:
        raise RuntimeError(f"tls-cert завершился с кодом {result.returncode}")


def _stamp(path: Path) -> tuple[int, int]:
    st = path.stat()
    return st.st_mtime_ns, st.st_size


def reload_if_changed(config: uvicorn.Config, cert: Path, key: Path,
                      last: tuple[int, int]) -> tuple[int, int]:
    """Если файл сертификата сменился - подгружает его в работающий контекст."""
    current = _stamp(cert)
    if current == last:
        return last
    context = getattr(config, "ssl", None)
    if context is None:
        # Сервер ещё не поднял SSL - подхватит файл сам при старте.
        return current
    context.load_cert_chain(str(cert), str(key))
    _log("новый сертификат подгружен без перезапуска")
    return current


def _watch(config: uvicorn.Config, tls_dir: str, stop: threading.Event) -> None:
    cert = Path(tls_dir) / "cert.pem"
    key = Path(tls_dir) / "key.pem"
    last = _stamp(cert)
    while not stop.wait(CHECK_SECONDS):
        try:
            ensure_cert(tls_dir)
            last = reload_if_changed(config, cert, key, last)
        except Exception as exc:  # noqa: BLE001 - продление не должно ронять панель
            _log(f"проверка сертификата не удалась: {exc}; повторю через {CHECK_SECONDS} с")


def listen_host(host: str) -> str:
    """0.0.0.0 -> :: (двойной стек), если на хосте есть IPv6 и ядро слушает
    :: сразу и по IPv4. Иначе остаётся как было: панель не должна пропасть из
    IPv4 из-за того, что на сервере IPv6 нет или bindv6only=1."""
    if host != "0.0.0.0" or not socket.has_ipv6:
        return host
    try:
        if open("/proc/sys/net/ipv6/bindv6only").read().strip() != "0":
            return host
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            probe.bind(("::", 0))
    except OSError:
        return host
    return "::"


def bind_dual_stack(port: int) -> socket.socket:
    """Сокет на :: с принятием и IPv4. asyncio при host="::" сам включает
    IPV6_V6ONLY, и IPv4 пропадал бы, поэтому сокет собираем руками и отдаём
    uvicorn готовым."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", port))
        sock.listen(2048)
        sock.set_inheritable(True)
    except OSError:
        sock.close()
        raise
    return sock


def main(argv: list[str]) -> None:
    if len(argv) != 4:
        sys.exit("использование: tls_serve МОДУЛЬ:APP ХОСТ ПОРТ КАТАЛОГ_TLS")
    app, host, port, tls_dir = argv
    ensure_cert(tls_dir)
    sockets = None
    if listen_host(host) == "::":
        try:
            sockets = [bind_dual_stack(int(port))]
        except OSError as exc:
            _log(f"двойной стек не вышел ({exc}) - слушаю только IPv4")
    config = uvicorn.Config(
        app, host=host, port=int(port),
        ssl_keyfile=str(Path(tls_dir) / "key.pem"),
        ssl_certfile=str(Path(tls_dir) / "cert.pem"),
    )
    server = uvicorn.Server(config)
    stop = threading.Event()
    threading.Thread(target=_watch, args=(config, tls_dir, stop),
                     name="tls-renew", daemon=True).start()
    try:
        server.run(sockets=sockets)
    finally:
        stop.set()


if __name__ == "__main__":
    main(sys.argv[1:])
