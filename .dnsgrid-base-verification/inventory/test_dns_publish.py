import copy
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client, TestCase
from django.urls import reverse

from .archives import restore, snapshot, validate
from .exporters import build_exports, publish_dns_zones
from .models import MAX_SERIAL, Configuration, Host, Site
from .services import save_host, update_settings


class DNSPublicationTests(TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.config = Configuration.load()
        self.config.dns_export_directory = str(self.path)
        self.config.save()
        self.user = get_user_model().objects.create_user(username="operator", is_staff=True)
        self.client.force_login(self.user)
        self.url = reverse("dns-publish")

    def publish(self):
        return self.client.post(self.url, {"revision": Configuration.load().revision}, follow=True)

    def sites(self):
        return list(Site.objects.values("id", "name", "g", "dsm_ifname"))

    def test_explicit_publication_overwrites_only_zone_files(self):
        host = Host(name="alpha", site_id=1, row=1, column=0)
        save_host(host, self.config.revision)
        artifacts = build_exports()
        forward = self.path / self.config.lan_domain
        forward.write_text("old content")
        previous_mode = stat.S_IMODE(forward.stat().st_mode)
        unrelated = self.path / "keep.txt"
        unrelated.write_text("unrelated")
        response = self.publish()
        self.assertContains(response, "DNS zone files written:")
        self.assertEqual(forward.read_text(), artifacts["forward.zone"])
        self.assertEqual(stat.S_IMODE(forward.stat().st_mode), previous_mode)
        for group in range(1, 5):
            filename = f"{group}.168.192.in-addr.arpa"
            self.assertEqual((self.path / filename).read_text(), artifacts[f"reverse-{group}.zone"])
            self.assertEqual(stat.S_IMODE((self.path / filename).stat().st_mode), 0o644)
            self.assertContains(response, filename)
        self.assertEqual(unrelated.read_text(), "unrelated")
        self.assertEqual(len(list(self.path.iterdir())), 8)
        revision = Configuration.load().revision
        self.publish()
        self.assertEqual(Configuration.load().revision, revision)
        self.assertEqual(forward.read_text(), artifacts["forward.zone"])

    def test_settings_hosts_previews_and_downloads_never_publish(self):
        updated = update_settings({"ttl": 600}, self.sites(), self.config.revision)
        save_host(Host(name="alpha", site_id=1, row=1, column=0), updated.revision)
        response = self.client.get(reverse("exports"))
        self.assertContains(response, str(self.path))
        self.assertContains(response, reverse("dns-publish"))
        for filename in response.context["artifacts"]:
            self.assertEqual(self.client.get(reverse("download", args=[filename])).status_code, 200)
        self.assertEqual(list(self.path.iterdir()), [])
        missing = self.path / "not-created"
        update_settings({"dns_export_directory": str(missing)}, self.sites(), Configuration.load().revision)
        self.assertFalse(missing.exists())

    def test_post_operator_csrf_and_revision_are_required(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)
        anonymous = Client()
        self.assertEqual(anonymous.post(self.url).status_code, 302)
        self.user.is_staff = False
        self.user.save()
        self.assertEqual(self.client.post(self.url).status_code, 403)
        self.user.is_staff = True
        self.user.save()
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(self.url, {"revision": self.config.revision}).status_code, 403)
        for data in ({}, {"revision": 0}, {"revision": "invalid"}):
            response = self.client.post(self.url, data, follow=True)
            self.assertContains(response, "Reload export previews before publishing")
        self.assertEqual(list(self.path.iterdir()), [])

    def test_disabled_and_missing_directory_errors(self):
        Configuration.objects.update(dns_export_directory="")
        self.assertContains(self.publish(), "Configure a DNS export directory")
        Configuration.objects.update(dns_export_directory=str(self.path / "missing"))
        response = self.publish()
        self.assertContains(response, "DNS zone write failed")
        self.assertFalse((self.path / "missing").exists())
        self.assertEqual(list(self.path.iterdir()), [])

    def test_failed_replace_retains_old_file_and_reports_partial_success(self):
        reverse_file = self.path / "1.168.192.in-addr.arpa"
        reverse_file.write_text("previous zone")
        replace = os.replace

        def fail_one(source, target):
            if Path(target) == reverse_file:
                raise PermissionError("write denied")
            return replace(source, target)

        with patch("inventory.exporters.os.replace", side_effect=fail_one):
            response = self.publish()
        self.assertContains(response, "DNS zone files written:")
        self.assertContains(response, "DNS zone write failed for 1.168.192.in-addr.arpa: write denied")
        self.assertEqual(reverse_file.read_text(), "previous zone")
        self.assertTrue((self.path / self.config.lan_domain).exists())
        self.assertFalse(any(file.name.startswith(".dnsgrid-") for file in self.path.iterdir()))

    def test_existing_zone_permissions_and_group_are_preserved(self):
        forward = self.path / self.config.lan_domain
        forward.write_text("previous zone")
        forward.chmod(0o640)
        group = forward.stat().st_gid
        self.publish()
        self.assertEqual(stat.S_IMODE(forward.stat().st_mode), 0o640)
        self.assertEqual(forward.stat().st_gid, group)

    def test_failure_preserving_metadata_retains_existing_file(self):
        forward = self.path / self.config.lan_domain
        forward.write_text("previous zone")
        with patch("inventory.exporters.os.fchmod", side_effect=PermissionError("mode denied")):
            response = self.publish()
        self.assertContains(response, "mode denied")
        self.assertEqual(forward.read_text(), "previous zone")
        self.assertEqual(list(self.path.iterdir()), [forward])

    def test_failed_temp_write_never_truncates_target(self):
        forward = self.path / self.config.lan_domain
        forward.write_text("previous zone")
        with patch("inventory.exporters.os.fsync", side_effect=OSError("disk error")):
            written, errors = publish_dns_zones(str(self.config.revision))
        self.assertEqual(written, [])
        self.assertEqual(len(errors), 5)
        self.assertEqual(forward.read_text(), "previous zone")
        self.assertEqual(list(self.path.iterdir()), [forward])

    def test_destination_symlink_is_replaced_not_followed(self):
        unrelated = self.path / "keep.txt"
        unrelated.write_text("do not touch")
        forward = self.path / self.config.lan_domain
        forward.symlink_to(unrelated)
        self.publish()
        self.assertFalse(forward.is_symlink())
        self.assertEqual(unrelated.read_text(), "do not touch")

    def test_invalid_directory_and_zone_filename_are_rejected(self):
        for value in ("relative/path", "/tmp/bad\x00path"):
            with self.assertRaises(ValidationError):
                update_settings({"dns_export_directory": value}, self.sites(), self.config.revision)
        Configuration.objects.update(lan_domain="../outside")
        with self.assertRaises(ValidationError):
            publish_dns_zones(str(self.config.revision))
        self.assertEqual(list(self.path.iterdir()), [])

    def test_colliding_zone_filenames_are_rejected_before_any_write(self):
        Configuration.objects.update(lan_domain="2.168.192.in-addr.arpa")
        response = self.publish()
        self.assertContains(response, "Forward and reverse zones must have distinct publication filenames")
        self.assertEqual(list(self.path.iterdir()), [])

    def test_serial_can_be_seeded_upward_and_downloads_do_not_increment(self):
        updated = update_settings({"soa_serial": 2026100803}, self.sites(), self.config.revision)
        self.assertEqual(updated.revision, self.config.revision + 1)
        self.assertEqual(updated.soa_serial, 2026100803)
        self.assertIn("        2026100803\n", build_exports()["forward.zone"])
        self.assertEqual(build_exports(), build_exports())
        self.assertEqual(Configuration.load().revision, updated.revision)
        same = update_settings({"soa_serial": updated.soa_serial}, self.sites(), updated.revision)
        self.assertEqual(same.revision, updated.revision)
        for serial in (updated.soa_serial - 1, MAX_SERIAL + 1, True):
            with self.assertRaises(ValidationError):
                update_settings({"soa_serial": serial}, self.sites(), updated.revision)
        save_host(Host(name="alpha", site_id=1, row=1, column=0), updated.revision)
        self.assertEqual(Configuration.load().revision, updated.revision + 1)
        self.assertEqual(Configuration.load().soa_serial, updated.soa_serial + 1)

    def test_archive_soa_round_trip_legacy_defaults_and_local_directory_preserved(self):
        updated = update_settings({
            "soa_refresh": 123, "soa_retry": 45, "soa_expire": 6789,
            "soa_minimum": 60, "zone_ns": "dns.example.test",
        }, self.sites(), self.config.revision)
        data = snapshot()
        self.assertNotIn("dns_export_directory", data["configuration"])
        self.assertEqual(validate(copy.deepcopy(data)), data)
        restore(data, updated.revision)
        current = Configuration.load()
        self.assertEqual(current.soa_refresh, 123)
        self.assertEqual(current.zone_ns, "dns.example.test")
        self.assertEqual(current.dns_export_directory, str(self.path))
        legacy = copy.deepcopy(data)
        for field in ("soa_refresh", "soa_retry", "soa_expire", "soa_minimum", "zone_ns"):
            legacy["configuration"].pop(field)
        normalized = validate(legacy)
        self.assertEqual(normalized["configuration"]["zone_ns"], data["configuration"]["soa_ns"])
        self.assertEqual(normalized["configuration"]["soa_refresh"], 3600)
        self.assertEqual(list(self.path.iterdir()), [])
