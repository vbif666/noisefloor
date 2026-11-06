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
        self.render = self.text.split("render_rules() {", 1)[1].split("cmd_up() {", 1)[0]
        self.up = self.text.split("cmd_up() {", 1)[1].split("cmd_check() {", 1)[0]
        self.down = self.text.split("cmd_down() {", 1)[1]

    def test_every_chain_created_in_up_is_removed_in_down(self):
        created = set(re.findall(r'ensure_chain \w+ "\$(\w+)"', self.render))
        removed = set(re.findall(r'drop_chain \w+ \w+ "\$(\w+)"', self.down))
        self.assertTrue(created)
        self.assertEqual(created - removed, set(), "цепочка создаётся, но не снимается в down")

    def test_redirect_returns_local_networks_before_the_cascade(self):
        redirect = self.render.split("redirect)", 1)[1].split(";;", 1)[0]
        self.assertIn("for net in $LOCAL_NETS", redirect)
        self.assertLess(
            redirect.index("LOCAL_NETS"), redirect.index("-p tcp -j REDIRECT"),
            "исключения обязаны стоять раньше правила перехвата",
        )

    def test_mss_is_clamped_in_both_directions(self):
        clamps = re.findall(r'-i "\$(\w+)" -o "\$(\w+)" \\\n\s+-p tcp .*TCPMSS', self.render)
        self.assertIn(("IFACE", "EGRESS"), clamps)
        self.assertIn(("EGRESS", "IFACE"), clamps)

    def test_cascade_port_is_closed_for_everything_but_the_tunnel(self):
        self.assertIn('-A "$IN_CHAIN" -i "$IFACE" -j RETURN', self.render)
        self.assertIn('-p tcp --dport "$CASCADE_PORT" -j DROP', self.render)

    def test_quic_is_rejected_not_dropped(self):
        # DROP заставил бы браузер ждать таймаута, прежде чем взять TCP.
        self.assertRegex(self.render, r'--dport 443 \\\n\s+-j REJECT --reject-with icmp-port-unreachable')

    def test_no_rule_bypasses_the_transaction(self):
        # Отдельный "iptables -A" вернул бы ровно то, что здесь чинили: код
        # возврата никто не смотрит, и половина правил встаёт молча.
        self.assertNotRegex(self.render + self.up, r'(?m)^\s*iptables ')

    def test_interception_goes_before_filter(self):
        # filter разрешает форвардинг. Если он встанет раньше перехвата, а
        # перехват не встанет, клиенты выйдут напрямую с адреса панели.
        self.assertIn('_order="mangle nat filter"', self.up)
        self.assertIn('redirect) _order="nat mangle filter"', self.up)

    def test_failed_restore_stops_the_script(self):
        restore = self.text.split("restore_table() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("if ! _err=", restore)
        self.assertIn("die ", restore)

    def test_foreign_routing_table_is_never_flushed(self):
        code = [l for l in self.text.splitlines() if not l.lstrip().startswith("#")]
        self.assertFalse([l for l in code if "ip route flush" in l])

    def test_mark_and_table_are_not_the_common_defaults(self):
        self.assertRegex(self.text, r'(?m)^MARK=0x4e46$')
        self.assertRegex(self.text, r'(?m)^RT_TABLE=20231$')

    def test_blocked_quic_bypasses_tproxy(self):
        # TPROXY в mangle/PREROUTING срабатывает раньше FORWARD: без
        # исключения закрытый QUIC всё равно уехал бы в каскад.
        tproxy = self.up.split("tproxy)", 1)[1].split(";;", 1)[0]
        self.assertIn('-p udp --dport 443 -j RETURN', tproxy)
        self.assertLess(
            tproxy.index("--dport 443 -j RETURN"), tproxy.index("-p udp \\\n"),
            "исключение QUIC обязано стоять раньше правила перехвата UDP",
        )


if __name__ == "__main__":
    unittest.main()


class MultipleInterfacesTests(unittest.TestCase):
    """Один вызов ставит правила для всех протоколов (awg0, awg-v1,
    wg-plain). Цепочки общие и очищаются перед заполнением, поэтому
    отдельный вызов на интерфейс стёр бы правила соседей."""

    def setUp(self):
        self.text = SCRIPT.read_text(encoding="utf-8")
        self.up = self.text.split("render_rules() {", 1)[1].split("cmd_up() {", 1)[0]

    def test_iface_flag_accumulates(self):
        self.assertIn('--iface)         IFACES="${IFACES:+$IFACES }$2"', self.text)

    def test_every_per_interface_rule_is_inside_a_loop(self):
        # Любое правило с -i/-o "$IFACE" вне цикла молча применилось бы
        # только к последнему интерфейсу из списка.
        loops = []  # стек открытых циклов: True — цикл по интерфейсам
        for line in self.up.splitlines():
            stripped = line.strip()
            if stripped.startswith("for ") and stripped.endswith("; do"):
                loops.append(stripped.startswith("for IFACE in $IFACES"))
            elif stripped == "done" and loops:
                loops.pop()
            elif '"$IFACE"' in stripped:
                self.assertIn(True, loops, f"правило вне цикла по интерфейсам: {stripped}")
