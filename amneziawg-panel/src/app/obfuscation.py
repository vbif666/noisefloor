"""
Случайная генерация параметров обфускации AmneziaWG 2.0.

Это ОДИН профиль на весь туннель: Jc/Jmin/Jmax/S1-S4/H1-H4 — параметры
маскировки заголовков и подмешивания мусорных пакетов на уровне интерфейса,
они должны быть побайтово одинаковыми на сервере и у КАЖДОГО его клиента,
иначе сторона-получатель не опознает входящий пакет как WireGuard-трафик
и хендшейк не пройдёт. Функции здесь используются только для генерации
профиля сервера (см. bootstrap.py, routers/server.py) — клиентские конфиги
берут те же значения из ServerConfig (awg_config.client_config).

Диапазоны соответствуют рекомендациям из документации/README amneziawg-go:
- Jc: рекомендуется 4-12
- Jmin/Jmax: держим заметно ниже типичного MTU (1500), чтобы junk-пакеты
  не фрагментировались (это демаскирует трафик)
- S1-S3: 0-64 байта, S4: 0-32 байта
- H1-H4: 4 числа в пределах uint32, гарантированно не пересекающиеся
"""
import random

_H_SPACE_START = 5  # избегаем 0 (означает "выключено") и 1-4 (зарезервированы под типы пакетов WireGuard)
_H_SPACE_END = 2_000_000_000  # с запасом внутри uint32, чтобы не думать про переполнение
_BAND_SIZE = (_H_SPACE_END - _H_SPACE_START) // 4


def random_headers() -> tuple[str, str, str, str]:
    """
    4 непересекающихся случайных числа (uint32) для H1..H4.

    Протокол AmneziaWG ждёт в каждом из полей H1-H4 ОДНО целое число
    (magic-значение, которым подменяется байт типа пакета), а не диапазон —
    и это число обязано быть одинаковым на сервере и на всех его клиентах,
    иначе сторона-получатель не опознает входящий пакет.
    """
    values = []
    for i in range(4):
        band_start = _H_SPACE_START + i * _BAND_SIZE
        band_end = band_start + _BAND_SIZE
        values.append(str(random.randint(band_start, band_end - 1)))
    return tuple(values)  # type: ignore[return-value]


def random_junk() -> tuple[int, int, int]:
    """Jc, Jmin, Jmax."""
    jc = random.randint(4, 12)
    jmin = random.randint(40, 120)
    jmax = jmin + random.randint(20, 200)
    return jc, jmin, jmax


def random_paddings() -> tuple[int, int, int, int]:
    """S1, S2, S3, S4."""
    return (
        random.randint(0, 64),
        random.randint(0, 64),
        random.randint(0, 64),
        random.randint(0, 32),
    )


def random_obfuscation_profile() -> dict:
    jc, jmin, jmax = random_junk()
    s1, s2, s3, s4 = random_paddings()
    h1, h2, h3, h4 = random_headers()
    return {
        "jc": jc, "jmin": jmin, "jmax": jmax,
        "s1": s1, "s2": s2, "s3": s3, "s4": s4,
        "h1": h1, "h2": h2, "h3": h3, "h4": h4,
    }
