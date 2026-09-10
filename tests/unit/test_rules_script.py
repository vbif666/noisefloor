"""
noisefloor-rules — сам скрипт правил.

Проверять его целиком без root и без сетевых namespace нельзя, поэтому
здесь закреплены те свойства, потеря которых уже стоила аварий, и они
видны прямо в тексте скрипта:

  * цепочка, созданная в up, обязана удаляться в down. Иначе повторные
    запуски копят правила — на ru2 их набралось по семь комплектов;
  * в redirect-режиме служебные сети обязаны обходить каскад. В
    tproxy-ветке такое исключение было с самого начала, а в redirect его
    не было: TCP к самой панели (10.13.13.1:8000) и к соседям по туннелю
    уезжал в каскад и умирал там по таймауту;
  * MSS подрезается в обе стороны. Раньше правился только клиентский SYN,
    а SYN-ACK удалённого сервера уходил нетронутым — и крупные загрузки
    вставали на сетях с меньшим MTU.
"""
import pathlib
import re
import unittest

def _find_script() -> pathlib.Path:
    """Тесты гоняют и из репозитория, и внутри образа, где каталог с ними
    примонтирован как /tests, а сам скрипт лежит в /usr/local/bin."""
    here = pathlib.Path(__file__).resolve()
    candidates = [parent / "amneziawg-panel" / "noisefloor-rules" for parent in here.parents]
    candidates.append(pathlib.Path("/usr/local/bin/noisefloor-rules"))
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError("не найден noisefloor-rules")


SCRIPT = _find_script()


class RulesScriptTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding="utf-8")
        self.up = self.text.split("cmd_up() {", 1)[1].split("cmd_down() {", 1)[0]
        self.down = self.text.split("cmd_down() {", 1)[1]

    def test_every_chain_created_in_up_is_removed_in_down(self):
        created = set(re.findall(r'ensure_chain \w+ "\$(\w+)"', self.up))
        removed = set(re.findall(r'drop_chain \w+ \w+ "\$(\w+)"', self.down))
        self.assertTrue(created)
        self.assertEqual(created - removed, set(), "цепочка создаётся, но не снимается в down")

    def test_redirect_returns_local_networks_before_the_cascade(self):
        redirect = self.up.split("redirect)", 1)[1].split(";;", 1)[0]
        self.assertIn("for net in $LOCAL_NETS", redirect)
        self.assertLess(
            redirect.index("LOCAL_NETS"), redirect.index("-p tcp -j REDIRECT"),
            "исключения обязаны стоять раньше правила перехвата",
        )

    def test_mss_is_clamped_in_both_directions(self):
        clamps = re.findall(r'-i "\$(\w+)" -o "\$(\w+)" \\\n\s+-p tcp .*TCPMSS', self.up)
        self.assertIn(("IFACE", "EGRESS"), clamps)
        self.assertIn(("EGRESS", "IFACE"), clamps)

    def test_cascade_port_is_closed_for_everything_but_the_tunnel(self):
        self.assertIn('-A "$IN_CHAIN" -i "$IFACE" -j RETURN', self.up)
        self.assertIn('-p tcp --dport "$CASCADE_PORT" -j DROP', self.up)

    def test_quic_is_rejected_not_dropped(self):
        # DROP заставил бы браузер ждать таймаута, прежде чем взять TCP.
        self.assertRegex(self.up, r'--dport 443 \\\n\s+-j REJECT --reject-with icmp-port-unreachable')


if __name__ == "__main__":
    unittest.main()
