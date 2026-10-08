import copy
import fcntl
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .archives import restore, snapshot
from .dns_notify import notify_nas, validate_destination
from .dns_publication import publish_and_notify, read_generation, retry_nas_update
from .exporters import build_exports
from .models import Configuration, Host, Site
from .services import save_host, update_settings


@override_settings(DNSGRID_DNS_SSH_IDENTITY_FILE="/etc/dnsgrid/id_ed25519",
                   DNSGRID_DNS_SSH_KNOWN_HOSTS="/etc/dnsgrid/known_hosts")
class DNSWorkflowTests(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        Configuration.objects.update(
            dns_export_directory=str(self.path), soa_serial=2026100800,
            dns_nas_host="dns-nas.example.test", dns_nas_user="dns-update", dns_nas_port=2222,
        )
        self.clock = patch("inventory.dns_serial.initial_serial", return_value=2026100800)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.ssh = patch("inventory.dns_notify.subprocess.run", return_value=SimpleNamespace(returncode=0))
        self.run = self.ssh.start()
        self.addCleanup(self.ssh.stop)
        self.user = get_user_model().objects.create_user("operator", is_staff=True)
        self.client.force_login(self.user)

    def publish(self):
        return publish_and_notify(str(Configuration.load().revision))

    def test_manifest_hashes_precise_generation_and_noop_is_immutable(self):
        exports = build_exports()
        written, errors, status, _ = self.publish()
        self.assertEqual((len(written), errors, status), (5, [], "success"))
        config = Configuration.load()
        path, manifest = read_generation(str(self.path), config.dns_published_generation)
        self.assertEqual(manifest["serial"], config.soa_serial)
        self.assertEqual(manifest["version"], 1)
        self.assertEqual(manifest["generation"], "dnsgrid-2026100800")
        for zone in manifest["zones"]:
            data = (path / zone["filename"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), zone["sha256"])
            self.assertEqual(len(data), zone["size"])
        self.assertEqual((path / config.lan_domain).read_text(), exports["forward.zone"])
        raw = (path / "manifest.json").read_bytes()
        self.publish()
        self.assertEqual((path / "manifest.json").read_bytes(), raw)
        self.assertEqual(json.loads((self.path / "manifest.json").read_bytes()), manifest)
        self.assertEqual(Configuration.load().soa_serial, config.soa_serial)
        self.assertFalse((path / ".pin").exists())

    def test_notification_uses_fixed_verb_strict_keys_argv_and_discards_output(self):
        self.publish()
        args, kwargs = self.run.call_args
        argv = args[0]
        self.assertEqual(argv[-3:], ["--", "dns-nas.example.test",
                                    "dnsgrid-update dnsgrid-2026100800 2026100800"])
        for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes",
                       "ConnectTimeout=5", "UserKnownHostsFile=/etc/dnsgrid/known_hosts"):
            self.assertIn(option, argv)
        self.assertIn("/etc/dnsgrid/id_ed25519", argv)
        self.assertIn("2222", argv)
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["timeout"], 120)
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)

    def test_partial_zone_or_generation_failure_does_not_notify_or_commit_latest(self):
        replace = os.replace
        target = self.path / "1.168.192.in-addr.arpa"
        with patch("inventory.exporters.os.replace", side_effect=lambda src, dst:
                   (_ for _ in ()).throw(OSError("denied")) if Path(dst) == target else replace(src, dst)):
            _, errors, _, _ = self.publish()
        self.assertTrue(errors)
        self.run.assert_not_called()
        self.assertFalse((self.path / "manifest.json").exists())
        with patch("inventory.dns_publication.os.link", side_effect=OSError("generation denied")):
            _, errors, _, _ = self.publish()
        self.assertTrue(errors)
        self.run.assert_not_called()
        self.assertFalse((self.path / "manifest.json").exists())
        self.assertFalse((self.path / "generations/dnsgrid-2026100800/manifest.json").exists())

    def test_manifest_write_failure_removes_uncommitted_application_files(self):
        from . import dns_publication
        atomic = dns_publication._atomic

        def fail_manifest(path, content, **kwargs):
            if path.name == "manifest.json":
                raise OSError("manifest denied")
            return atomic(path, content, **kwargs)

        with patch("inventory.dns_publication._atomic", side_effect=fail_manifest):
            _, errors, _, _ = self.publish()
        self.assertTrue(errors)
        self.run.assert_not_called()
        self.assertFalse((self.path / "generations/dnsgrid-2026100800").exists())

    def test_manifest_is_committed_after_all_zone_files(self):
        from . import dns_publication
        atomic = dns_publication._atomic
        seen = []

        def observe(path, data, **kwargs):
            if path.name == "manifest.json":
                for filename in (Configuration.load().lan_domain, "1.168.192.in-addr.arpa",
                                 "2.168.192.in-addr.arpa", "3.168.192.in-addr.arpa", "4.168.192.in-addr.arpa"):
                    self.assertTrue((path.parent / filename).exists())
            seen.append(path)
            return atomic(path, data, **kwargs)

        with patch("inventory.dns_publication._atomic", side_effect=observe):
            self.publish()
        manifests = [path for path in seen if path.name == "manifest.json"]
        self.assertEqual(manifests[-1], self.path / "manifest.json")
        self.assertEqual(seen[-1].name, ".pin")

    def test_same_serial_collision_is_rejected_before_mutable_overwrite(self):
        self.publish()
        config = Configuration.load()
        original = (self.path / config.lan_domain).read_bytes()
        Configuration.objects.update(ttl=600, dns_content_hash="")
        with self.assertRaisesMessage(ValidationError, "Same serial"):
            self.publish()
        self.assertEqual((self.path / config.lan_domain).read_bytes(), original)

    def test_timeout_and_transport_ambiguity_pin_exact_retry_without_serial_advance(self):
        self.run.side_effect = subprocess.TimeoutExpired("ssh", 120, output=b"<secret>")
        _, errors, status, summary = self.publish()
        self.assertEqual((errors, status), ([], "unconfirmed"))
        self.assertNotIn("secret", summary)
        config = Configuration.load()
        generation = config.dns_published_generation
        path, _ = read_generation(str(self.path), generation)
        self.assertTrue((path / ".pin").exists())
        save_host(Host(name="alpha", site_id=1, row=1, column=0), config.revision)
        serial = Configuration.load().soa_serial
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(returncode=255)
        self.assertEqual(retry_nas_update(Configuration.load().revision, generation)[0], "unconfirmed")
        self.run.return_value = SimpleNamespace(returncode=0)
        self.assertEqual(retry_nas_update(Configuration.load().revision, generation)[0], "success")
        self.assertEqual(Configuration.load().soa_serial, serial)
        self.assertIn(f"dnsgrid-update {generation} {config.soa_serial}", self.run.call_args.args[0])
        self.assertFalse((path / ".pin").exists())

    def test_concurrent_notification_returns_retry_and_leaves_generation_pinned(self):
        self.publish()
        with open(self.path / ".dnsgrid-notify.lock", "rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run.reset_mock()
            _, errors, status, summary = self.publish()
        self.assertEqual((errors, status), ([], "failure"))
        self.assertIn("another NAS notification", summary)
        self.run.assert_not_called()
        config = Configuration.load()
        path, _ = read_generation(str(self.path), config.dns_published_generation)
        self.assertTrue((path / ".pin").exists())
        self.assertEqual(retry_nas_update(config.revision, config.dns_published_generation)[0], "success")

    def test_disabled_and_missing_deployment_settings_do_not_spawn_ssh(self):
        Configuration.objects.update(dns_nas_host="", dns_nas_user="")
        self.assertEqual(self.publish()[2], "disabled")
        self.run.assert_not_called()
        Configuration.objects.update(dns_nas_host="dns.example.test", dns_nas_user="dns-update")
        with override_settings(DNSGRID_DNS_SSH_IDENTITY_FILE=""):
            self.assertEqual(self.publish()[2], "failure")
        self.run.assert_not_called()

    def test_destination_and_request_injection_are_rejected(self):
        for host, user, port in (("-oProxyCommand=evil", "dns", 22), ("a;evil", "dns", 22),
                                 ("a", "-o", 22), ("a", "root;evil", 22), ("a", "dns", True),
                                 ("fe80::1%;evil", "dns", 22),
                                 ("a", "dns", 0), ("", "dns", 22)):
            with self.assertRaises(ValidationError):
                validate_destination(host, user, port)
        for host in ("nas.example.test", "192.0.2.1", "2001:db8::1"):
            validate_destination(host, "dns-update", 22)
        with self.assertRaises(ValidationError):
            notify_nas(Configuration.load(), "../escape", 2026100800)
        self.run.assert_not_called()

    def test_safe_bounded_retention_preserves_unrelated_and_pins(self):
        self.publish()
        root = self.path / "generations"
        unrelated = root / "dnsgrid-2026100700"
        unrelated.mkdir()
        (unrelated / "keep").write_text("unrelated")
        symlink = root / "dnsgrid-2026100600"
        symlink.symlink_to(unrelated, target_is_directory=True)
        first = root / "dnsgrid-2026100800"
        (first / ".pin").write_text("pending")
        for serial in range(2026100801, 2026100812):
            Configuration.objects.update(soa_serial=serial)
            self.publish()
        owned = [p for p in root.iterdir() if not p.is_symlink() and (p / "manifest.json").exists()]
        self.assertEqual(len(owned), 10)
        self.assertTrue(first.exists())
        self.assertTrue((unrelated / "keep").exists())
        self.assertTrue(symlink.is_symlink())
        for p in owned:
            (p / ".pin").write_text("unconfirmed")
        Configuration.objects.update(soa_serial=2026100812)
        _, errors, _, _ = self.publish()
        self.assertIn("retention", str(errors))
        self.assertEqual(len([p for p in root.iterdir() if (p / "manifest.json").exists()]), 10)

    def test_retry_ui_permissions_csrf_staleness_and_archive_deployment_exclusion(self):
        response = self.client.get(reverse("exports"))
        self.assertContains(response, "Publish zones and update NAS")
        self.assertNotContains(response, "Retry NAS update</button>")
        self.publish()
        config = Configuration.load()
        response = self.client.get(reverse("exports"))
        self.assertContains(response, "Retry NAS update")
        url = reverse("dns-retry")
        data = {"revision": config.revision, "generation": config.dns_published_generation}
        self.assertEqual(self.client.get(url).status_code, 405)
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.user)
        self.assertEqual(csrf.post(url, data).status_code, 403)
        self.assertEqual(Client().post(url, data).status_code, 302)
        self.user.is_staff = False
        self.user.save()
        self.assertEqual(self.client.post(url, data).status_code, 403)
        with self.assertRaises(ValidationError):
            retry_nas_update(config.revision + 1, config.dns_published_generation)
        archive = snapshot()
        for field in ("dns_nas_host", "dns_nas_user", "dns_nas_port", "dns_published_generation", "dns_content_hash"):
            self.assertNotIn(field, archive["configuration"])
        restore(copy.deepcopy(archive), config.revision)
        self.assertEqual(Configuration.load().dns_nas_host, config.dns_nas_host)
        self.assertEqual(Configuration.load().dns_published_generation, config.dns_published_generation)
        self.assertEqual(Configuration.load().soa_serial, config.soa_serial)
