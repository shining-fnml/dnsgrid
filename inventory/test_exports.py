import json

from django.test import TestCase
from django.core.exceptions import ValidationError

from .exporters import build_exports, desired_gandi
from .models import Configuration, Host, Site


class ExportTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.host = Host.objects.create(
            name="alpha", site=Site.objects.get(pk=1), row=2, column=3,
            vpn=True, public_export=True, mac="02:00:00:00:00:01",
            notes="PRIVATE-NOTE",
        )

    def test_forward_reverse_dhcp_and_vpn(self):
        output = build_exports()
        self.assertIn("$ORIGIN intranet.example.tld.", output["forward.zone"])
        self.assertIn("$TTL 300", output["forward.zone"])
        self.assertIn("ns.example.tld. hostmaster.intranet.example.tld.", output["forward.zone"])
        self.assertIn("alpha IN A 192.168.1.50", output["forward.zone"])
        self.assertIn("$ORIGIN 1.168.192.in-addr.arpa.", output["reverse-1.zone"])
        self.assertIn("50 IN PTR alpha.intranet.example.tld.", output["reverse-1.zone"])
        self.assertIn("hardware ethernet 02:00:00:00:00:01;", output["dhcpd.conf"])
        self.assertIn("fixed-address alpha.intranet.example.tld;", output["dhcpd.conf"])
        self.assertNotIn("fixed-address 192.", output["dhcpd.conf"])
        self.assertIn("172.28.1.50 alpha.vpn.example.tld alpha", output["vpn.hosts"])
        for group in range(1, 5):
            self.assertIn(f"subnet 192.168.{group}.0 netmask 255.255.255.0", output["dhcpd.conf"])
            self.assertIn(f"reverse-{group}.zone", output)
        self.assertEqual(json.loads(output["gandi.json"]), [{
            "rrset_name": "alpha.vpn", "rrset_type": "A",
            "rrset_ttl": 300, "rrset_values": ["172.28.1.50"],
        }])
        self.assertNotIn("PRIVATE-NOTE", "".join(output.values()))
        self.assertNotIn(self.host.status, "".join(output.values()))

    def test_every_status_is_exported(self):
        for status, _ in Host._meta.get_field("status").choices:
            self.host.status = status
            output = build_exports(self.config, [self.host])
            self.assertIn("alpha IN A", output["forward.zone"])
            self.assertIn("50 IN PTR", output["reverse-1.zone"])
            self.assertIn("host alpha", output["dhcpd.conf"])
            self.assertEqual(len(json.loads(output["gandi.json"])), 1)
            self.assertNotIn(status, "".join(output.values()))

    def test_vpn_public_flags_and_optional_mac(self):
        for vpn in (False, True):
            for public in (False, True):
                self.host.vpn, self.host.public_export = vpn, public
                self.host.mac = ""
                output = build_exports(self.config, [self.host])
                self.assertEqual("alpha.vpn.example.tld" in output["vpn.hosts"], vpn)
                self.assertEqual(len(desired_gandi(self.config, [self.host])), int(vpn and public))
                self.assertNotIn("host alpha", output["dhcpd.conf"])
                self.assertIn("alpha IN A", output["forward.zone"])

    def test_move_and_custom_configuration(self):
        self.host.site = Site.objects.get(pk=4)
        self.config.lan_prefix = "10.24"
        self.config.vpn_prefix = "10.29"
        self.config.lan_domain = "lan.other.test"
        self.config.vpn_domain = "vpn.other.test"
        self.config.gandi_zone = "other.test"
        self.config.ttl = 600
        self.config.revision = 42
        self.config.soa_ns = "ns.lan.other.test"
        self.config.soa_mailbox = "admin.lan.other.test"
        output = build_exports(self.config, [self.host])
        self.assertIn("alpha IN A 10.24.4.50", output["forward.zone"])
        self.assertIn("42 3600", output["forward.zone"])
        self.assertIn("$TTL 600", output["forward.zone"])
        self.assertIn("$ORIGIN 4.24.10.in-addr.arpa.", output["reverse-4.zone"])
        self.assertIn("50 IN PTR alpha.lan.other.test.", output["reverse-4.zone"])
        self.assertNotIn("50 IN PTR", output["reverse-1.zone"])
        self.assertIn("10.29.4.50 alpha.vpn.other.test alpha", output["vpn.hosts"])
        self.assertEqual(desired_gandi(self.config, [self.host])[0]["rrset_values"], ["10.29.4.50"])

    def test_site_move_does_not_change_dhcp_reservations(self):
        beta = Host.objects.create(
            name="beta", site=Site.objects.get(pk=2), row=1, column=1,
            mac="02:00:00:00:00:02",
        )
        before = build_exports(self.config, [self.host, beta])
        self.host.site = Site.objects.get(pk=4)
        after = build_exports(self.config, [self.host, beta])
        self.assertEqual(before["dhcpd.conf"], after["dhcpd.conf"])
        self.assertNotEqual(before["forward.zone"], after["forward.zone"])
        self.assertLess(before["dhcpd.conf"].rindex("subnet "), before["dhcpd.conf"].index("host beta"))

    def test_negative_cache_ttl_does_not_exceed_low_configured_ttl(self):
        self.config.ttl = 30
        output = build_exports(self.config, [])
        self.assertIn("1209600 30 )", output["forward.zone"])
        self.assertIn("1209600 30 )", output["reverse-1.zone"])

    def test_exporter_normalizes_directly_supplied_mac(self):
        for mac in ("020000000001", "02-00-00-00-00-01", "0200.0000.0001"):
            self.host.mac = mac
            self.assertIn(
                "hardware ethernet 02:00:00:00:00:01;",
                build_exports(self.config, [self.host])["dhcpd.conf"],
            )

    def test_exporter_rejects_invalid_directly_supplied_mac(self):
        for mac in ("bad-mac", "00:00:00:00:00:00", "01:00:00:00:00:01",
                    "02:00:00:00:00:01; malicious"):
            self.host.mac = mac
            with self.assertRaises(ValidationError):
                build_exports(self.config, [self.host])

    def test_exporter_rejects_duplicate_normalized_mac(self):
        beta = Host(name="beta", site=Site.objects.get(pk=2), row=1, column=1,
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

    def test_order_is_stable_and_by_address(self):
        beta = Host.objects.create(name="beta", site=Site.objects.get(pk=2), row=1, column=1)
        first = build_exports(self.config, [self.host, beta])
        self.assertEqual(first, build_exports(self.config, [beta, self.host]))
        self.assertLess(first["forward.zone"].index("beta IN A"), first["forward.zone"].index("alpha IN A"))
        self.assertEqual(build_exports(), build_exports())

    def test_public_name_outside_zone_is_rejected(self):
        self.config.gandi_zone = "unrelated.test"
        with self.assertRaises(ValueError):
            desired_gandi(self.config, [self.host])

    def test_empty_inventory_and_changed_site_group(self):
        Site.objects.filter(pk=4).update(g=17)
        output = build_exports(self.config, [])
        self.assertIn("reverse-17.zone", output)
        self.assertNotIn("reverse-4.zone", output)
        self.assertIn("$ORIGIN 17.168.192.in-addr.arpa.", output["reverse-17.zone"])
        self.assertIn("subnet 192.168.17.0", output["dhcpd.conf"])
        self.assertEqual(json.loads(output["gandi.json"]), [])
        self.assertNotIn(" IN A ", output["forward.zone"])
