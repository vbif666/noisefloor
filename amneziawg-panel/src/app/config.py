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

    # Запрещать клиентам видеть друг друга внутри туннеля. По умолчанию
    # выключено, чтобы не сломать сценарии вроде доступа к домашней машине
    # через тот же туннель.
    isolate_clients: bool = False

    def model_post_init(self, __context) -> None:
        if not self.secret_key:
            object.__setattr__(self, "secret_key", _get_or_create_secret_key())


settings = Settings()
