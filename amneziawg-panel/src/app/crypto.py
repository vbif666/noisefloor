"""
Генерация ключей Curve25519 в формате, совместимом с WireGuard/AmneziaWG
(`wg genkey` / `awg genkey`): 32 случайных байта с "клэмпингом" по RFC 7748,
закодированные в base64.

Клэмпинг применяется явно, а не полагается на детали конкретной реализации
криптобиблиотеки — это гарантирует побайтовую совместимость с ключами,
которые генерирует сам awg/wg.
"""
import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _clamp(raw: bytearray) -> bytes:
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return bytes(raw)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def public_key_from_private(private_key_b64: str) -> str:
    raw = base64.b64decode(private_key_b64)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64(pub_raw)


def generate_keypair() -> tuple[str, str]:
    """Возвращает (private_key_b64, public_key_b64)."""
    raw = _clamp(bytearray(os.urandom(32)))
    private_b64 = _b64(raw)
    public_b64 = public_key_from_private(private_b64)
    return private_b64, public_b64


def generate_preshared_key() -> str:
    return _b64(os.urandom(32))
