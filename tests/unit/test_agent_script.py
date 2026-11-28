"""
tools/noisefloor — агент обновлений на хосте.

Скрипт идёт под set -euo pipefail, поэтому любой конвейер, где читатель
закрывает канал раньше писателя, может уронить обновление. Так и было до
v1.0.26: `docker compose config --images | head -1` при панели с канарейкой
(две строки, один образ) примерно в половине запусков возвращал 255, и кнопка
«Обновить» молча не срабатывала сразу после «проверяю».
"""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


def _find_script() -> pathlib.Path:
    """Из репозитория или внутри образа в CI, где скрипт примонтирован
    в /usr/local/bin, а каталог с тестами - как /tests."""
    here = pathlib.Path(__file__).resolve()
    candidates = [parent / "tools" / "noisefloor" for parent in here.parents]
    candidates.append(pathlib.Path("/usr/local/bin/noisefloor"))
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError("не найден tools/noisefloor")


SCRIPT = _find_script()

# Поддельный docker: первая строка, пауза (чтобы читатель успел закрыть
# канал), вторая строка. Ошибку записи превращает в 255, как настоящий.
FAKE_DOCKER = """#!/usr/bin/env bash
trap '' PIPE
printf 'vbif666/noisefloor-amneziawg-panel:latest\\n' || exit 255
sleep 0.2
printf 'vbif666/noisefloor-amneziawg-panel:latest\\n' || exit 255
"""


class AgentScriptTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding="utf-8")

    def test_no_head_after_compose_images(self):
        self.assertNotRegex(self.text, r"config --images\s*\|\s*head")

    def test_pull_has_timeout(self):
        self.assertRegex(self.text, r'timeout "\$PULL_TIMEOUT" docker pull')
        self.assertNotRegex(self.text, r"^\s*docker pull", "pull мимо pull_image")

    @unittest.skipUnless(shutil.which("bash"), "нужен bash")
    def test_compose_image_survives_early_close(self):
        func = re.search(r"^compose_image\(\) \{.*\}$", self.text, re.M)
        self.assertIsNotNone(func, "нет функции compose_image")
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / "docker"
            fake.write_text(FAKE_DOCKER, encoding="utf-8", newline="\n")
            fake.chmod(0o755)
            snippet = f"set -euo pipefail\n{func.group(0)}\nref=$(compose_image .)\necho \"$ref\"\n"
            env = dict(os.environ, PATH=f"{tmp}{os.pathsep}{os.environ.get('PATH', '')}")
            res = subprocess.run([shutil.which("bash"), "-c", snippet], cwd=tmp, env=env,
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), "vbif666/noisefloor-amneziawg-panel:latest")


if __name__ == "__main__":
    unittest.main()
