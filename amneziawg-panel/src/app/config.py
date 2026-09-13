"""
Централизованные настройки приложения.
Значения читаются из переменных окружения / файла .env (см. .env.example).
"""
from pathlib import Path
import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


def _get_or_create_secret_key() -> str:
    """
    SECRET_KEY нужен для подписи JWT. Если он не задан явно через .env,
    генерируем случайный один раз и сохраняем в data/secret_key,
    чтобы токены не "слетали" при каждом перезапуске сервиса.
    """
    key_file = DATA_DIR / "secret_key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    key_file.chmod(0o600)
    return key


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(BASE_DIR / ".env"), env_file_encoding="utf-8", extra="ignore")

    # --- Аутентификация панели ---
    secret_key: str = ""
    admin_username: str = "admin"
    admin_password: str = ""  # если пусто — при первом запуске сгенерируется случайный пароль
    access_token_expire_minutes: int = 720  # 12 часов

    # --- База данных ---
    database_url: str = f"sqlite:///{DATA_DIR / 'awg_panel.db'}"

    # --- AmneziaWG / сервер ---
    awg_interface: str = "awg0"
    awg_config_dir: str = "/etc/amnezia/amneziawg"
    egress_interface: str = "eth0"
    live_management_enabled: bool = True
    default_server_address: str = "10.13.13.1/24"
    # 443/UDP вместо стандартного 51820: этот порт почти никогда не блокируют
    # фаерволы/DPI (по нему ходит легитимный QUIC/HTTP3-трафик), поэтому WG-пакеты
    # на нём не выделяются на фоне обычного "как будто HTTPS" трафика.
    default_listen_port: int = 443
    default_dns: str = "1.1.1.1"

    # Docker-шаблон: поднять интерфейс автоматически при старте контейнера,
    # без ручного нажатия "Apply" в панели. Оригинальный (не-docker) деплой
    # на systemd этого не делал — там администратор жал Apply руками после
    # первичной настройки. В контейнере такого шага быть не должно.
    auto_apply_on_start: bool = True

    # Как перехватывать клиентский трафик в каскад:
    #   tproxy   — TCP и UDP, то есть QUIC и DNS тоже идут через каскад.
    #              Единственный режим, в котором каскад делает то, что обещает.
    #   redirect — только TCP (у REDIRECT нет аналога для UDP). Оставлен как
    #              путь отката: UDP при нём уходит напрямую с реальным IP.
    cascade_intercept_mode: str = "tproxy"

    # Резать ли клиентам QUIC (UDP/443), пока каскад работает в режиме
    # redirect. В этом режиме UDP в каскад не заворачивается и уходит
    # напрямую с настоящим адресом сервера, а браузер предпочитает QUIC
    # обычному TCP — то есть основная часть трафика идёт мимо каскада и с
    # чужим IP. Отказ по icmp-port-unreachable заставляет браузер сразу
    # взять TCP; задержки при этом не возникает. В режиме tproxy настройка
    # не действует: там QUIC и так идёт через каскад.
    cascade_block_quic: bool = True

    # Заворачивать ли DNS клиентов в каскад в режиме redirect: панель
    # поднимает свой слушатель, запрос уходит наружу по TCP через каскад.
    # По умолчанию выключено: каждый несохранённый в кэше запрос дорожает
    # примерно на один обход каскада, а адрес назначения TCP-соединений и
    # так выбирает релей (вход каскада разбирает домен из TLS/HTTP).
    # Включайте, если важно, чтобы DNS-резолвер не видел адрес сервера.
    cascade_dns_via_cascade: bool = False

    # Откуда панель узнаёт о своих обновлениях:
    #   stable — релизы GitHub (тег vX.Y.Z с заметками). Плашка появляется,
    #            когда автор сознательно выпустил версию.
    #   latest — каждый коммит в master. Свежее, но без гарантий.
    update_channel: str = "stable"

    # Запрещать клиентам видеть друг друга внутри туннеля. Включено по
    # умолчанию: устройства в общем туннеле не должны получать доступ друг
    # к другу просто потому, что подключены к одному серверу.
    #
    # Выключайте осознанно — например, если через этот же туннель ходите
    # с ноутбука на домашнюю машину.
    isolate_clients: bool = True

    def model_post_init(self, __context) -> None:
        if not self.secret_key:
            object.__setattr__(self, "secret_key", _get_or_create_secret_key())


settings = Settings()
