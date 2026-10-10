import copy
import json
from urllib.parse import parse_qs

from django.core.exceptions import ValidationError
from django.test import TestCase

from synology.dsm_apply import validate_payload

from .archives import dumps, loads, restore, snapshot
from .dsm import reservation_form_body, reservation_payload, reservation_request
from .exporters import build_exports
from .models import Configuration, Host, Site
from .services import update_settings


class DSMReservationTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.site = Site.objects.get(pk=1)
        self.site.dsm_ifname = "ovs_eth0"
        self.site.save(update_fields=["dsm_ifname"])
        self.alpha = Host.objects.create(
            name="alpha", site=self.site, row=2, column=3, mac="02:aa:bb:cc:dd:ee",
            status=Host.Status.DECOMMISSIONED, notes="private notes",
        )
        self.beta = Host.objects.create(
            name="beta", site=self.site, row=1, column=0, mac="02:00:00:00:00:02",
        )
        self.no_mac = Host.objects.create(name="no-mac", site=self.site, row=2, column=0)
        self.other = Host.objects.create(
            name="other", site_id=2, row=3, column=0, mac="02:00:00:00:00:03",
        )
        self.hosts = [self.alpha, self.other, self.no_mac, self.beta]

    def test_payload_shape_membership_and_grid_order(self):
        expected = {
            "ifname": "ovs_eth0",
            "reservationData": [
                {"mac": "02:00:00:00:00:02", "ip": "192.168.1.1", "hostname": "beta"},
                {"mac": "02:aa:bb:cc:dd:ee", "ip": "192.168.1.50", "hostname": "alpha"},
            ],
        }
        self.assertEqual(reservation_payload(self.config, self.site, self.hosts), expected)
        self.assertEqual(validate_payload(expected), expected)
        exports = build_exports(self.config, self.hosts)
        self.assertEqual(json.loads(exports["dsm-reservations-site-1.json"]), expected)
        self.assertNotIn("dsm-reservations-site-2.json", exports)
        self.assertNotIn("private notes", exports["dsm-reservations-site-1.json"])

    def test_mac_normalization_and_invalid_nonempty_macs_fail_closed(self):
        for mac in ("02AABBCCDDEE", "02-AA-BB-CC-DD-EE", "02aa.bbcc.ddee",
                    " 02:AA:BB:CC:DD:EE; "):
            self.alpha.mac = mac
            self.assertEqual(reservation_payload(
                self.config, self.site, [self.alpha],
            )["reservationData"][0]["mac"], "02:aa:bb:cc:dd:ee")
        for mac in ("bad", "00:00:00:00:00:00", "01:00:00:00:00:01"):
            self.alpha.mac = mac
            with self.assertRaises(ValidationError):
                reservation_payload(self.config, self.site, [self.alpha])
        self.alpha.mac = "020000000002"
        with self.assertRaises(ValueError):
            reservation_payload(self.config, self.site, self.hosts)

    def test_request_parameters_and_exact_form_encoding(self):
        params = reservation_request(self.config, self.site, self.hosts)
        self.assertEqual(set(params), {
            "api", "method", "version", "stop_when_error", "mode", "compound",
        })
        self.assertEqual(params["api"], "SYNO.Entry.Request")
        self.assertEqual(params["method"], "request")
        self.assertEqual(params["version"], 1)
        self.assertEqual(params["stop_when_error"], "false")
        self.assertEqual(params["mode"], '"sequential"')
        self.assertEqual(json.loads(params["compound"]), [{
            "api": "SYNO.Network.DHCPServer.Reservation", "method": "set", "version": 2,
            **reservation_payload(self.config, self.site, self.hosts),
        }])
        body = reservation_form_body(self.config, self.site, self.hosts)
        self.assertEqual(parse_qs(body), {key: [str(value)] for key, value in params.items()})
        self.assertNotIn("dsm-request-site-1.form", build_exports(self.config, self.hosts))

    def test_changed_subnet_interface_and_site_move(self):
        self.config.lan_prefix = "10.24"
        self.site.g = 17
        self.site.dsm_ifname = "bond0"
        payload = reservation_payload(self.config, self.site, [self.alpha])
        self.assertEqual(payload["ifname"], "bond0")
        self.assertEqual(payload["reservationData"][0]["ip"], "10.24.17.50")
        other_site = self.other.site
        other_site.dsm_ifname = "ovs_eth1"
        self.alpha.site = other_site
        self.assertEqual(reservation_payload(
            self.config, self.site, [self.alpha],
        )["reservationData"], [])
        self.assertEqual(reservation_payload(
            self.config, other_site, [self.alpha],
        )["reservationData"][0]["ip"], "10.24.2.50")

    def test_empty_list_and_interface_validation(self):
        self.assertEqual(reservation_payload(self.config, self.site, []), {
            "ifname": "ovs_eth0", "reservationData": [],
        })
        for ifname in ("../etc", "ovs eth0", "a" * 16, "ovs_eth0\n"):
            self.site.dsm_ifname = ifname
            with self.assertRaises(ValidationError):
                reservation_payload(self.config, self.site, [])
        self.site.dsm_ifname = ""
        with self.assertRaises(ValueError):
            reservation_payload(self.config, self.site, [])

    def test_deterministic_exports_and_multiple_site_targets(self):
        Site.objects.filter(pk=2).update(dsm_ifname="ovs_eth1")
        before = build_exports(self.config, self.hosts)
        self.assertEqual(before, build_exports(self.config, reversed(self.hosts)))
        self.assertEqual(build_exports(), build_exports())
        self.assertEqual(json.loads(before["dsm-reservations-site-2.json"]), {
            "ifname": "ovs_eth1", "reservationData": [
                {"mac": "02:00:00:00:00:03", "ip": "192.168.2.3", "hostname": "other"},
            ],
        })

    def test_mapping_mutations_claim_revision_and_preserve_legacy_service_calls(self):
        sites = list(Site.objects.values("id", "name", "g", "dsm_ifname"))
        sites[0]["dsm_ifname"] = "bond0"
        revision = self.config.revision
        updated = update_settings({}, sites, revision)
        self.assertEqual(updated.revision, revision + 1)
        self.assertEqual(Site.objects.get(pk=1).dsm_ifname, "bond0")
        with self.assertRaises(ValidationError):
            update_settings({}, sites, revision)
        self.assertEqual(update_settings({}, sites, updated.revision).revision, updated.revision)
        legacy = [{key: site[key] for key in ("id", "name", "g")} for site in sites]
        update_settings({}, legacy, updated.revision)
        self.assertEqual(Site.objects.get(pk=1).dsm_ifname, "bond0")
        sites[0]["dsm_ifname"] = ""
        update_settings({}, sites, updated.revision)
        self.assertNotIn("dsm-reservations-site-1.json", build_exports())

    def test_archive_mapping_round_trip_and_old_v1_compatibility(self):
        data = snapshot()
        self.assertEqual(loads(dumps(data).encode()), data)
        Site.objects.filter(pk=1).update(dsm_ifname="bond0")
        restore(data, self.config.revision)
        self.assertEqual(Site.objects.get(pk=1).dsm_ifname, "ovs_eth0")
        legacy = copy.deepcopy(data)
        for site in legacy["sites"]:
            site.pop("dsm_ifname")
        restored = loads(dumps(legacy).encode())
        self.assertTrue(all(site["dsm_ifname"] == "" for site in restored["sites"]))
        restore(legacy, Configuration.load().revision)
        self.assertEqual(Site.objects.get(pk=1).dsm_ifname, "")
        for value in ("../invalid", None, 1):
            invalid = copy.deepcopy(data)
            invalid["sites"][0]["dsm_ifname"] = value
            with self.assertRaises(ValidationError):
                loads(dumps(invalid).encode())
