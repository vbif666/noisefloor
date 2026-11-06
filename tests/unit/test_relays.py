"""
Список релеев каскада.

Главное здесь - что ничего не изменилось для тех, у кого релей один, и что
откат на прошлую версию панели не теряет основной релей: она читает столбцы
server_config и про таблицу cascade_relays не знает.
"""
import unittest
from types import SimpleNamespace
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import awg_config, cascade, cascade_sync, relays
from app.database import Base
from app.models import CascadeRelay, ServerConfig


def url(host: str) -> str:
    return (
        f"vless://00000000-0000-4000-8000-0000000000ff@{host}:8443"
        "?type=tcp&security=reality&pbk=EXAMPLEpublickeyEXAMPLEpublickeyEXAMPLEpub"
        "&fp=chrome&sni=dl.google.com&sid=0123456789abcdef&flow=xtls-rprx-vision#r"
    )


A = cascade.parse_vless_url(url("203.0.113.10"))
B = cascade.parse_vless_url(url("203.0.113.20"))


def make_db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False)()


def make_server(db, **columns) -> ServerConfig:
    server = ServerConfig(
        private_key="k", public_key="p", address="10.0.0.1/24", listen_port=1,
        endpoint_host="h", cascade_enabled=True, **columns,
    )
    db.add(server)
    db.commit()
    return server


class PrimaryRecordTests(unittest.TestCase):
    def setUp(self):
        self.db = make_db()

    def test_existing_relay_moves_into_table(self):
        server = make_server(self.db, cascade_vless_url=url("203.0.113.10"),
                             cascade_sync_url="https://r:8001", cascade_sync_token="t",
                             cascade_sync_cert_pin="key:aa|u")
        relays.pull_primary(self.db, server)
        row = relays.primary(server)
        self.assertEqual(row.position, 0)
        self.assertEqual(row.vless_url, url("203.0.113.10"))
        self.assertEqual(row.sync_cert_pin, "key:aa|u")

    def test_transfer_is_idempotent(self):
        server = make_server(self.db, cascade_vless_url=url("203.0.113.10"))
        relays.pull_primary(self.db, server)
        relays.pull_primary(self.db, server)
        self.assertEqual(self.db.query(CascadeRelay).count(), 1)

    def test_no_empty_record_without_cascade_settings(self):
        server = make_server(self.db)
        relays.pull_primary(self.db, server)
        self.assertEqual(self.db.query(CascadeRelay).count(), 0)

    def test_columns_win_after_rollback_to_old_version(self):
        # Старая версия поменяла столбцы, про запись она не знает.
        server = make_server(self.db, cascade_vless_url=url("203.0.113.10"))
        relays.pull_primary(self.db, server)
        server.cascade_vless_url = url("203.0.113.99")
        self.db.commit()
        relays.pull_primary(self.db, server)
        self.assertEqual(relays.primary(server).vless_url, url("203.0.113.99"))

    def test_sync_result_reaches_columns_for_rollback(self):
        server = make_server(self.db, cascade_vless_url=url("203.0.113.10"))
        relays.pull_primary(self.db, server)
        relays.primary(server).vless_url = url("203.0.113.77")
        relays.push_primary(server)
        self.assertEqual(server.cascade_vless_url, url("203.0.113.77"))

    def test_first_reserve_does_not_become_primary(self):
        server = make_server(self.db)
        reserve = relays.add_reserve(self.db, server, url("203.0.113.20"), "", "")
        self.assertEqual(reserve.position, 1)
        self.assertFalse(relays.primary(server).vless_url)

    def test_reserves_keep_order_and_survive_pull(self):
        server = make_server(self.db, cascade_vless_url=url("203.0.113.10"))
        relays.pull_primary(self.db, server)
        relays.add_reserve(self.db, server, url("203.0.113.20"), "", "")
        relays.add_reserve(self.db, server, url("203.0.113.30"), "", "")
        relays.pull_primary(self.db, server)
        self.assertEqual(cascade.relay_urls(server),
                         [url("203.0.113.10"), url("203.0.113.20"), url("203.0.113.30")])

    def test_relay_urls_without_table(self):
        # Сервер, на котором записи ещё не перенесены.
        server = SimpleNamespace(relays=[], cascade_vless_url=" " + url("203.0.113.10") + "\n")
        self.assertEqual(cascade.relay_urls(server), [url("203.0.113.10")])


class ConfigTests(unittest.TestCase):
    @staticmethod
    def rule(config, tag):
        return next(r for r in config["routing"]["rules"] if r.get("ruleTag") == tag)

    def test_single_relay_with_block_is_unchanged(self):
        config = cascade.build_xray_config(A)
        self.assertNotIn("burstObservatory", config)
        self.assertNotIn("balancers", config["routing"])
        self.assertEqual([o["tag"] for o in config["outbounds"]], ["cascade-out", "direct", "block"])
        self.assertEqual(self.rule(config, "nf-default")["outboundTag"], "cascade-out")

    def test_two_relays(self):
        config = cascade.build_xray_config(A, reserves=[B])
        self.assertEqual([o["tag"] for o in config["outbounds"]][:2], ["cascade-out", "cascade-out-2"])
        default = self.rule(config, "nf-default")
        self.assertEqual(default["balancerTag"], "relays")
        self.assertNotIn("outboundTag", default)

    def test_selector_never_matches_direct_or_block(self):
        config = cascade.build_xray_config(A, reserves=[B], all_down="direct")
        prefix = config["burstObservatory"]["subjectSelector"][0]
        matched = [o["tag"] for o in config["outbounds"] if o["tag"].startswith(prefix)]
        self.assertEqual(matched, ["cascade-out", "cascade-out-2"])

    def test_direct_applies_to_clients_not_to_probe(self):
        # Иначе при direct проба вышла бы напрямую и показала здоровый каскад.
        config = cascade.build_xray_config(A, all_down="direct")
        balancers = {b["tag"]: b for b in config["routing"]["balancers"]}
        self.assertEqual(balancers["relays"]["fallbackTag"], "direct")
        self.assertEqual(balancers["relays-probe"]["fallbackTag"], "cascade-out")
        self.assertEqual(self.rule(config, "nf-probe")["balancerTag"], "relays-probe")

    def test_block_never_falls_back_to_direct(self):
        config = cascade.build_xray_config(A, reserves=[B], all_down="block")
        for balancer in config["routing"]["balancers"]:
            self.assertEqual(balancer["fallbackTag"], "cascade-out")

    def test_probe_url_goes_to_observatory(self):
        with mock.patch.object(cascade.settings, "cascade_probe_url", "http://example.test/204"):
            config = cascade.build_xray_config(A, reserves=[B])
        self.assertEqual(config["burstObservatory"]["pingConfig"]["destination"],
                         "http://example.test/204")

    def test_dns_in_redirect_mode_follows_balancer(self):
        with mock.patch.object(cascade, "dns_via_cascade", return_value=True):
            config = cascade.build_xray_config(A, reserves=[B])
        rule = next(r for r in config["routing"]["rules"] if r.get("inboundTag") == ["dns-in"])
        self.assertEqual(rule["balancerTag"], "relays")
        self.assertNotIn("dns-out", [o["tag"] for o in config["outbounds"]])

    def test_ru_split_goes_through_balancer_too(self):
        config = cascade.build_xray_config(A, split_ru_direct=True, reserves=[B])
        fixed = [r for r in config["routing"]["rules"] if r.get("outboundTag") == "cascade-out"]
        # Правило мимо балансировщика не заметило бы смерти основного релея.
        self.assertEqual(fixed, [])


class ActiveRelayTests(unittest.TestCase):
    OUTPUT = (
        "  - Selecting Override:\n"
        "    1                 \n"
        "  - Selects:\n"
        "    1   cascade-out-2   \n"
    )

    def test_real_output_of_xray_api_bi(self):
        self.assertEqual(cascade._selected_tag(self.OUTPUT), "cascade-out-2")

    def test_nothing_selected(self):
        self.assertIsNone(cascade._selected_tag("  - Selects:\n"))
        self.assertIsNone(cascade._selected_tag(""))


class AllDownTests(unittest.TestCase):
    def test_unknown_mode_is_block(self):
        self.assertEqual(cascade.all_down_mode(SimpleNamespace(cascade_all_down="?")), "block")

    def test_suspended_only_in_direct_without_xray(self):
        def state(enabled, mode, running):
            server = SimpleNamespace(cascade_enabled=enabled, cascade_all_down=mode)
            with mock.patch.object(cascade, "is_running", return_value=running):
                return cascade.intercept_suspended(server)

        self.assertTrue(state(True, "direct", False))
        self.assertFalse(state(True, "direct", True))
        self.assertFalse(state(True, "block", False))
        self.assertFalse(state(False, "direct", False))

    def test_restart_delays_reach_ceiling(self):
        self.assertEqual(cascade.restart_delay(0), 1)
        self.assertEqual(cascade.restart_delay(1), 2)
        self.assertEqual(cascade.restart_delay(1000), 60)


class SyncByRelayTests(unittest.TestCase):
    ANSWER = {"uuid": "00000000-0000-4000-8000-0000000000ff", "port": 8443,
              "public_key": "pk", "sni": "dl.google.com", "host": "203.0.113.20"}

    def setUp(self):
        self.db = make_db()
        self.server = make_server(
            self.db, cascade_sync_url="https://a:8001", cascade_sync_token="ta",
            cascade_vless_url=url("203.0.113.10"), cascade_sync_cert_pin="pa",
        )
        relays.pull_primary(self.db, self.server)
        self.reserve = relays.add_reserve(self.db, self.server, url("203.0.113.20"),
                                          "https://b:8001", "tb")
        self.reserve.sync_cert_pin = "pb"
        self.db.commit()
        patches = [
            mock.patch("app.config_sync.get_server", return_value=self.server),
            mock.patch.object(cascade, "sync", return_value=None),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(cascade_sync._rotations.clear)

    def test_each_relay_keeps_its_token_and_pin(self):
        seen = {}

        def fetch(sync_url, token, pin):
            seen[sync_url] = (token, pin)
            return dict(self.ANSWER), "key:new"

        with mock.patch.object(cascade_sync, "fetch_params", side_effect=fetch):
            cascade_sync.sync_once(self.db)
        self.assertEqual(seen, {"https://a:8001": ("ta", "pa"), "https://b:8001": ("tb", "pb")})

    def test_one_dead_relay_does_not_stop_the_other(self):
        def fetch(sync_url, token, pin):
            if "a:8001" in sync_url:
                raise cascade_sync.SyncError("нет связи")
            return dict(self.ANSWER), "key:new"

        with mock.patch.object(cascade_sync, "fetch_params", side_effect=fetch):
            _changed, error = cascade_sync.sync_once(self.db)
        self.assertIn("a: нет связи", error)
        self.assertEqual(self.server.cascade_sync_error, "нет связи")
        self.assertIsNone(self.reserve.sync_error)
        self.assertTrue(self.reserve.sync_cert_pin.startswith("key:new|"))

    def test_primary_change_reaches_columns(self):
        answer = dict(self.ANSWER, host="203.0.113.55")
        with mock.patch.object(cascade_sync, "fetch_params", return_value=(answer, "key:new")):
            changed, _ = cascade_sync.sync_once(self.db)
        self.assertTrue(changed)
        self.assertIn("203.0.113.55", self.server.cascade_vless_url)
        cascade.sync.assert_called()

    def test_nearest_rotation_of_all_relays_wins(self):
        def fetch(sync_url, token, pin):
            at = "2030-01-01T00:00:00+00:00" if "a:" in sync_url else "2029-01-01T00:00:00+00:00"
            return dict(self.ANSWER, rotation={"enabled": True, "next_at": at}), "key:new"

        with mock.patch.object(cascade_sync, "fetch_params", side_effect=fetch):
            cascade_sync.sync_once(self.db)
        self.assertEqual(cascade_sync.next_rotation_at.year, 2029)


class RulesTests(unittest.TestCase):
    def _commands(self, mode):
        db = make_db()
        server = make_server(db, cascade_vless_url=url("203.0.113.10"), cascade_all_down=mode)
        with mock.patch.object(cascade, "is_running", return_value=False), \
             mock.patch.object(cascade, "_tproxy_mode", return_value=True):
            return str(awg_config.rules_commands(server, ["awg0"]))

    def test_rules_keep_intercept_in_block_without_xray(self):
        self.assertNotEqual(self._commands("block"), self._commands("direct"))

    def test_block_rules_equal_rules_with_running_xray(self):
        db = make_db()
        server = make_server(db, cascade_vless_url=url("203.0.113.10"), cascade_all_down="direct")
        with mock.patch.object(cascade, "is_running", return_value=True), \
             mock.patch.object(cascade, "_tproxy_mode", return_value=True):
            running = str(awg_config.rules_commands(server, ["awg0"]))
        self.assertEqual(running, self._commands("block"))


if __name__ == "__main__":
    unittest.main()
