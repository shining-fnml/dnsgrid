import json

from django.test import TestCase
from django.core.exceptions import ValidationError

from .exporters import build_exports, desired_gandi
from .models import Configuration, Host, Site


class ExportTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        Site.objects.update(dsm_ifname="eth0")
        self.host = Host.objects.create(
            name="alpha", site=Site.objects.get(pk=1), row=2, column=3,
            vpn=True, public_export=True, mac="02:00:00:00:00:01",
            notes="PRIVATE-NOTE",
        )

    def test_forward_reverse_and_vpn(self):
        output = build_exports()
        self.assertIn("$ORIGIN intranet.example.tld.", output["forward.zone"])
        self.assertIn("$TTL 300", output["forward.zone"])
        self.assertIn("ns.example.tld. hostmaster.intranet.example.tld.", output["forward.zone"])
        self.assertIn("alpha.intranet.example.tld. 300 A 192.168.1.50", output["forward.zone"])
        self.assertIn("$ORIGIN 1.168.192.in-addr.arpa.", output["reverse-1.zone"])
        self.assertIn("50.1.168.192.in-addr.arpa. 300 PTR alpha.intranet.example.tld.", output["reverse-1.zone"])
        self.assertNotIn("dhcpd.conf", output)
        self.assertNotIn("dhcpd-dsm.conf", output)
        self.assertFalse(any(name.endswith(".form") for name in output))
        self.assertIn("$ORIGIN vpn.", output["vpn.zone"])
        self.assertIn("alpha.vpn. 300 A 172.28.1.50", output["vpn.zone"])
        self.assertIn("$ORIGIN 28.172.in-addr.arpa.", output["reverse-vpn.zone"])
        self.assertIn("50.1.28.172.in-addr.arpa. 300 PTR alpha.vpn.", output["reverse-vpn.zone"])
        self.assertNotIn("vpn.example.tld", output["vpn.zone"])
        self.assertNotIn("vpn.hosts", output)
        for group in range(1, 5):
            self.assertIn(f"reverse-{group}.zone", output)
        self.assertEqual(json.loads(output["gandi.json"]), [{
            "rrset_name": "alpha.vpn", "rrset_type": "A",
            "rrset_ttl": 300, "rrset_values": ["172.28.1.50"],
        }, {
            "rrset_name": "alpha.intranet", "rrset_type": "A",
            "rrset_ttl": 300, "rrset_values": ["192.168.1.50"],
        }])
        self.assertNotIn("PRIVATE-NOTE", "".join(output.values()))
        self.assertNotIn(self.host.status, "".join(output.values()))

    def test_hub_private_zone_origins_are_configured_lan_and_vpn(self):
        self.config.lan_domain = "intranet.linuxcondom.net"
        self.config.vpn_domain = "vpn.linuxcondom.net"
        self.config.gandi_zone = "linuxcondom.net"
        output = build_exports(self.config, [self.host])
        self.assertIn("$ORIGIN intranet.linuxcondom.net.", output["forward.zone"])
        self.assertIn("alpha.intranet.linuxcondom.net. 300 A 192.168.1.50", output["forward.zone"])
        self.assertIn("$ORIGIN vpn.", output["vpn.zone"])
        self.assertIn("alpha.vpn. 300 A 172.28.1.50", output["vpn.zone"])

    def test_every_status_is_exported(self):
        original = build_exports(self.config, [self.host])
        for status, _ in Host._meta.get_field("status").choices:
            self.host.status = status
            output = build_exports(self.config, [self.host])
            self.assertIn("alpha.intranet.example.tld. 300 A", output["forward.zone"])
            self.assertIn("50.1.168.192.in-addr.arpa. 300 PTR", output["reverse-1.zone"])
            self.assertEqual(json.loads(output["dsm-reservations-site-1.json"])["reservationData"][0]["hostname"], "alpha")
            self.assertEqual(len(json.loads(output["gandi.json"])), 2)
            self.assertNotIn(status, "".join(output.values()))
            self.assertEqual(output, original)
            self.assertEqual(self.host.name, "alpha")
            self.assertNotIn("(alpha)", "".join(output.values()))

    def test_vpn_public_flags_and_optional_mac(self):
        for vpn in (False, True):
            for public in (False, True):
                self.host.vpn, self.host.public_export = vpn, public
                self.host.mac = ""
                output = build_exports(self.config, [self.host])
                self.assertEqual("alpha.vpn. 300 A 172.28.1.50\n" in output["vpn.zone"], vpn)
                self.assertEqual(
                    "50.1.28.172.in-addr.arpa. 300 PTR alpha.vpn.\n" in output["reverse-vpn.zone"], vpn,
                )
                self.assertEqual(
                    [record["rrset_name"] for record in desired_gandi(self.config, [self.host])],
                    ["alpha.vpn", "alpha.intranet"] if vpn and public else [],
                )
                self.assertEqual(json.loads(output["dsm-reservations-site-1.json"])["reservationData"], [])
                self.assertIn("alpha.intranet.example.tld. 300 A", output["forward.zone"])

    def test_move_and_custom_configuration(self):
        self.host.site = Site.objects.get(pk=4)
        self.config.lan_prefix = "10.24"
        self.config.vpn_prefix = "10.29"
        self.config.lan_domain = "lan.other.test"
        self.config.vpn_domain = "vpn.other.test"
        self.config.gandi_zone = "other.test"
        self.config.ttl = 600
        self.config.revision = 42
        self.config.soa_serial = 2026100802
        self.config.soa_ns = "ns.lan.other.test"
        self.config.soa_mailbox = "admin.lan.other.test"
        self.config.zone_ns = "dns.other.test"
        self.config.soa_refresh = 123
        self.config.soa_retry = 45
        self.config.soa_expire = 6789
        self.config.soa_minimum = 60
        output = build_exports(self.config, [self.host])
        self.assertIn("alpha.lan.other.test. 600 A 10.24.4.50", output["forward.zone"])
        self.assertIn("lan.other.test. IN SOA ns.lan.other.test. admin.lan.other.test. (\n"
                      "        2026100802\n        123\n        45\n        6789\n        60\n)", output["forward.zone"])
        self.assertIn("$TTL 600", output["forward.zone"])
        self.assertIn("$ORIGIN 4.24.10.in-addr.arpa.", output["reverse-4.zone"])
        self.assertIn("50.4.24.10.in-addr.arpa. 600 PTR alpha.lan.other.test.", output["reverse-4.zone"])
        self.assertNotIn(" PTR ", output["reverse-1.zone"])
        self.assertTrue(output["forward.zone"].endswith("lan.other.test. NS dns.other.test.\n"))
        self.assertTrue(output["reverse-4.zone"].endswith("4.24.10.in-addr.arpa. NS dns.other.test.\n"))
        self.assertIn("alpha.vpn. 600 A 10.29.4.50\n", output["vpn.zone"])
        self.assertNotIn("vpn.other.test", output["vpn.zone"])
        self.assertIn("$ORIGIN 29.10.in-addr.arpa.", output["reverse-vpn.zone"])
        self.assertIn("50.4.29.10.in-addr.arpa. 600 PTR alpha.vpn.\n", output["reverse-vpn.zone"])
        self.assertTrue(output["reverse-vpn.zone"].endswith("29.10.in-addr.arpa. NS dns.other.test.\n"))
        self.assertEqual(json.loads(output["dsm-reservations-site-4.json"])["reservationData"][0]["ip"], "10.24.4.50")
        self.assertEqual(
            [(record["rrset_name"], record["rrset_ttl"], record["rrset_values"])
             for record in desired_gandi(self.config, [self.host])],
            [("alpha.vpn", 600, ["10.29.4.50"]), ("alpha.lan", 600, ["10.24.4.50"])],
        )

    def test_site_move_updates_reservations_and_zones(self):
        beta = Host.objects.create(
            name="beta", site=Site.objects.get(pk=2), row=1, column=1,
            mac="02:00:00:00:00:02",
        )
        before = build_exports(self.config, [self.host, beta])
        self.host.site = Site.objects.get(pk=4)
        after = build_exports(self.config, [self.host, beta])
        self.assertNotEqual(before["dsm-reservations-site-1.json"], after["dsm-reservations-site-1.json"])
        self.assertNotEqual(before["dsm-reservations-site-4.json"], after["dsm-reservations-site-4.json"])
        self.assertEqual(before["dsm-reservations-site-2.json"], after["dsm-reservations-site-2.json"])
        self.assertNotEqual(before["forward.zone"], after["forward.zone"])

    def test_negative_cache_ttl_is_explicit(self):
        self.config.ttl = 30
        self.config.soa_minimum = 12
        output = build_exports(self.config, [])
        self.assertIn("        1209600\n        12\n)", output["forward.zone"])
        self.assertIn("        1209600\n        12\n)", output["reverse-1.zone"])

    def test_exporter_normalizes_directly_supplied_mac(self):
        for mac in ("020000000001", "02-00-00-00-00-01", "0200.0000.0001"):
            self.host.mac = mac
            output = build_exports(self.config, [self.host])
            self.assertEqual(json.loads(output["dsm-reservations-site-1.json"])["reservationData"][0]["mac"],
                             "02:00:00:00:00:01")

    def test_exporter_rejects_invalid_directly_supplied_mac(self):
        for mac in ("bad-mac", "00:00:00:00:00:00", "01:00:00:00:00:01",
                    "02:00:00:00:00:01; malicious"):
            self.host.mac = mac
            with self.assertRaises(ValidationError):
                build_exports(self.config, [self.host])

    def test_exporter_rejects_duplicate_normalized_mac(self):
        beta = Host(name="beta", site=Site.objects.get(pk=1), row=1, column=1,
                    mac="0200.0000.0001")
        with self.assertRaises(ValueError):
            build_exports(self.config, [self.host, beta])

    def test_export_snapshot_locks_before_reading(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        with CaptureQueriesContext(connection) as queries:
            build_exports()
        sql = [query["sql"] for query in queries]
        lock = next(index for index, statement in enumerate(sql)
                    if statement.startswith('UPDATE "inventory_configuration"'))
        config_read = next(index for index, statement in enumerate(sql)
                           if statement.startswith("SELECT") and '"inventory_configuration"' in statement)
        hosts_read = next(index for index, statement in enumerate(sql)
                          if statement.startswith("SELECT") and '"inventory_host"' in statement)
        sites_read = next(index for index, statement in enumerate(sql)
                          if statement.startswith("SELECT") and '"inventory_site"."g"' in statement
                          and '"inventory_host"' not in statement)
        self.assertLess(lock, config_read)
        self.assertLess(config_read, hosts_read)
        self.assertLess(hosts_read, sites_read)

    def test_order_is_stable_and_by_hostname(self):
        beta = Host.objects.create(name="beta", site=Site.objects.get(pk=2), row=1, column=1)
        first = build_exports(self.config, [self.host, beta])
        self.assertEqual(first, build_exports(self.config, [beta, self.host]))
        self.assertLess(first["forward.zone"].index("alpha.intranet"), first["forward.zone"].index("beta.intranet"))
        self.assertEqual(build_exports(), build_exports())
        self.assertEqual(
            first["dsm-reservations-site-1.json"],
            build_exports(self.config, [beta, self.host])["dsm-reservations-site-1.json"],
        )
        beta.site = self.host.site
        reverse = build_exports(self.config, [beta, self.host])["reverse-1.zone"]
        self.assertLess(reverse.index("alpha.intranet"), reverse.index("beta.intranet"))
        self.assertNotIn("PRIVATE-NOTE", first["dsm-reservations-site-1.json"])

    def test_vpn_reverse_is_cumulative_and_deterministic(self):
        beta = Host(name="beta", site=Site.objects.get(pk=2), row=1, column=1, vpn=True)
        disabled = Host(name="disabled", site=Site.objects.get(pk=3), row=1, column=1)
        hosts = [beta, disabled, self.host]
        output = build_exports(self.config, hosts)
        reverse = output["reverse-vpn.zone"]
        self.assertEqual(output, build_exports(self.config, list(reversed(hosts))))
        self.assertIn("50.1.28.172.in-addr.arpa. 300 PTR alpha.vpn.\n", reverse)
        self.assertIn("17.2.28.172.in-addr.arpa. 300 PTR beta.vpn.\n", reverse)
        self.assertNotIn("disabled", reverse)
        self.assertEqual(reverse.count(" PTR "), 2)
        self.assertLess(reverse.index("alpha.vpn"), reverse.index("beta.vpn"))
        empty = build_exports(self.config, [])["reverse-vpn.zone"]
        self.assertIn("$ORIGIN 28.172.in-addr.arpa.", empty)
        self.assertNotIn(" PTR ", empty)

    def test_dsm_export_omits_hosts_without_mac_and_normalizes_macs(self):
        beta = Host.objects.create(name="beta", site=Site.objects.get(pk=2), row=1, column=1)
        self.host.mac = "020000000001"
        self.config.gandi_token = "PRIVATE-TOKEN"
        output = build_exports(self.config, [self.host, beta])["dsm-reservations-site-1.json"]
        self.assertEqual(json.loads(output)["reservationData"], [
            {"mac": "02:00:00:00:00:01", "hostname": "alpha", "ip": "192.168.1.50"},
        ])
        self.assertNotIn("beta", output)
        self.assertNotIn("PRIVATE-TOKEN", output)

    def test_public_name_outside_zone_is_rejected(self):
        self.config.gandi_zone = "unrelated.test"
        with self.assertRaises(ValueError):
            desired_gandi(self.config, [self.host])

    def test_lan_name_outside_zone_is_rejected_on_label_boundary(self):
        for lan_domain in ("intranet.other.test", "intranet.badexample.tld", "intranetexample.tld"):
            self.config.lan_domain = lan_domain
            with self.subTest(lan_domain=lan_domain), self.assertRaisesMessage(
                ValueError, f"LAN hostname alpha.{lan_domain} must be inside",
            ):
                build_exports(self.config, [self.host])
        self.host.public_export = False
        self.assertEqual(json.loads(build_exports(self.config, [self.host])["gandi.json"]), [])

    def test_colliding_gandi_names_are_rejected(self):
        self.config.lan_domain = self.config.vpn_domain
        with self.assertRaisesMessage(ValueError, "alpha.vpn.example.tld would be published twice"):
            desired_gandi(self.config, [self.host])
        self.config.lan_domain = "Intranet.Example.TLD."
        self.assertEqual(len(desired_gandi(self.config, [self.host])), 2)

    def test_gandi_pairs_are_ordered_by_host_then_vpn_and_lan(self):
        beta = Host.objects.create(
            name="beta", site=Site.objects.get(pk=2), row=1, column=1,
            vpn=True, public_export=True,
        )
        gamma = Host.objects.create(
            name="gamma", site=Site.objects.get(pk=3), row=1, column=2, vpn=True,
        )
        delta = Host.objects.create(
            name="delta", site=Site.objects.get(pk=4), row=1, column=4, public_export=True,
        )
        hosts = [self.host, beta, gamma, delta]
        expected = [
            ("beta.vpn", ["172.28.2.17"]), ("beta.intranet", ["192.168.2.17"]),
            ("alpha.vpn", ["172.28.1.50"]), ("alpha.intranet", ["192.168.1.50"]),
        ]
        for order in (hosts, list(reversed(hosts))):
            records = desired_gandi(self.config, order)
            self.assertEqual([(r["rrset_name"], r["rrset_values"]) for r in records], expected)
        self.assertEqual(
            build_exports(self.config, hosts)["gandi.json"],
            build_exports(self.config, list(reversed(hosts)))["gandi.json"],
        )

    def test_gandi_zone_apex_and_nested_domains(self):
        self.config.gandi_zone = "example.tld"
        self.config.vpn_domain = "example.tld"
        self.config.lan_domain = "lan.site.example.tld"
        self.assertEqual(
            [record["rrset_name"] for record in desired_gandi(self.config, [self.host])],
            ["alpha", "alpha.lan.site"],
        )

    def test_empty_inventory_and_changed_site_group(self):
        Site.objects.filter(pk=4).update(g=17)
        output = build_exports(self.config, [])
        self.assertIn("reverse-17.zone", output)
        self.assertNotIn("reverse-4.zone", output)
        self.assertIn("$ORIGIN 17.168.192.in-addr.arpa.", output["reverse-17.zone"])
        self.assertEqual(json.loads(output["gandi.json"]), [])
        self.assertNotIn(" A ", output["forward.zone"])
        for filename, content in output.items():
            if filename.endswith(".zone"):
                lines = content.splitlines()
                self.assertTrue(lines[0].startswith("$ORIGIN "))
                origin = lines[0].split()[1]
                self.assertEqual(lines[-1], f"{origin} NS ns.example.tld.")
