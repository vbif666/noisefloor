import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import backup, bootstrap, cascade, cascade_sync, config_sync, self_update, traffic_history
from .config import settings
from .database import Base, SessionLocal, engine, run_migrations
from .routers import auth, backup as backup_router, peers, server, status, updates

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


class RevalidatingStaticFiles(StaticFiles):
    """Статика с обязательной перепроверкой у сервера.

    Без Cache-Control браузер кэширует файлы по своему усмотрению, и после
    docker compose pull человек продолжает видеть СТАРЫЙ интерфейс: контейнер
    обновился, а app.js в браузере остался прежний. Выглядит это как «обновление
    не доехало» и заставляет искать поломку там, где её нет.

    no-cache не запрещает хранить копию — он требует спросить сервер, не
    изменился ли файл. ETag уже отдаётся, поэтому неизменившийся файл стоит
    один ответ 304 без тела."""

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response

_traffic_history_stop = threading.Event()
_cascade_supervisor_stop = threading.Event()
_backup_stop = threading.Event()
_cascade_sync_stop = threading.Event()
_self_update_stop = threading.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    run_migrations()
    db = SessionLocal()
    try:
        bootstrap.run(db)
        if settings.auto_apply_on_start:
            # Docker-шаблон: поднимаем awg0 сразу при старте, без ручного
            # клика "Apply" в UI. best-effort — если утилит awg нет в PATH
            # или live_management выключен, apply() сама вернёт ok=False,
            # панель всё равно останется рабочей как генератор конфигов.
            result = config_sync.apply_current_config(db)
            print(f"[startup] auto-apply awg0: ok={result.ok} {result.output}")
    finally:
        db.close()
    threading.Thread(target=traffic_history.run, args=(_traffic_history_stop,), daemon=True).start()
    # Надзор за каскадом: перезапускает упавший xray и регулярно проверяет
    # реальной пробой, что через каскад вообще идёт трафик.
    threading.Thread(target=cascade.supervise, args=(_cascade_supervisor_stop,), daemon=True).start()
    # Резервные копии: одна сразу при старте, дальше раз в сутки. В data
    # лежат ключи всех клиентов — без копий их потеря невосстановима.
    threading.Thread(target=backup.run, args=(_backup_stop,), daemon=True).start()
    # Синхронизация с релеем: подтягивает его SNI и camouflage dest, чтобы
    # их не приходилось держать одинаковыми на двух серверах руками.
    threading.Thread(target=cascade_sync.run, args=(_cascade_sync_stop,), daemon=True).start()
    # Проверка собственных обновлений: раз в шесть часов спрашивает, не
    # вышла ли новая версия, и показывает это в панели. Само обновление
    # делает хостовый агент по запросу администратора.
    threading.Thread(target=self_update.run, args=(_self_update_stop,), daemon=True).start()
    try:
        yield
    finally:
        _traffic_history_stop.set()
        _cascade_supervisor_stop.set()
        _backup_stop.set()
        _cascade_sync_stop.set()
        _self_update_stop.set()


app = FastAPI(title="AmneziaWG Panel", version="1.0.0", lifespan=lifespan)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(server.router, prefix="/api/server", tags=["server"])
app.include_router(peers.router, prefix="/api/peers", tags=["peers"])
app.include_router(status.router, prefix="/api/status", tags=["status"])
app.include_router(updates.router, prefix="/api/updates", tags=["updates"])
app.include_router(backup_router.router, prefix="/api/backup", tags=["backup"])

if STATIC_DIR.exists():
    app.mount("/", RevalidatingStaticFiles(directory=str(STATIC_DIR), html=True), name="static")
