import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from .archives import restore, snapshot
from .dns_publication import pending_generations, read_generation, validate_generation
from .exporters import build_exports, publish_dns_zones
from .models import Configuration


class DNSWorkflowTests(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        Configuration.objects.update(
            dns_export_directory=str(self.path), soa_serial=2026100800,
        )
        self.clock = patch("inventory.dns_serial.initial_serial", return_value=2026100800)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.user = get_user_model().objects.create_user("operator", is_staff=True)
        self.client.force_login(self.user)

    def publish(self):
        return publish_dns_zones(str(Configuration.load().revision))

    def test_manifest_hashes_precise_generation_and_noop_is_immutable(self):
        exports = build_exports()
        written, errors = self.publish()
        self.assertEqual((len(written), errors), (5, []))
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

    def test_partial_zone_or_generation_failure_does_not_commit_latest(self):
        replace = os.replace
        target = self.path / "1.168.192.in-addr.arpa"
        with patch("inventory.exporters.os.replace", side_effect=lambda src, dst:
                   (_ for _ in ()).throw(OSError("denied")) if Path(dst) == target else replace(src, dst)):
            _, errors = self.publish()
        self.assertTrue(errors)
        self.assertFalse((self.path / "manifest.json").exists())
        with patch("inventory.dns_publication.os.link", side_effect=OSError("generation denied")):
            _, errors = self.publish()
        self.assertTrue(errors)
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
            _, errors = self.publish()
        self.assertTrue(errors)
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
        self.assertEqual(seen[-1], self.path / "manifest.json")

    def test_same_serial_collision_is_rejected_before_mutable_overwrite(self):
        self.publish()
        config = Configuration.load()
        original = (self.path / config.lan_domain).read_bytes()
        Configuration.objects.update(ttl=600, dns_content_hash="")
        with self.assertRaisesMessage(ValidationError, "Same serial"):
            self.publish()
        self.assertEqual((self.path / config.lan_domain).read_bytes(), original)

    def test_generation_identifier_and_serial_validation_is_preserved(self):
        validate_generation("dnsgrid-2026100800", 2026100800)
        for generation, serial in (("../escape", 2026100800), ("dnsgrid-2026100801", 2026100800),
                                   ("dnsgrid-2026023000", 2026023000), ("dnsgrid-True", True)):
            with self.subTest(generation=generation), self.assertRaises(ValidationError):
                validate_generation(generation, serial)

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
        _, errors = self.publish()
        self.assertIn("retention", str(errors))
        self.assertEqual(len([p for p in root.iterdir() if (p / "manifest.json").exists()]), 10)

        self.assertEqual(len(pending_generations(str(self.path))), 10)

    def test_local_ui_and_legacy_archive_deployment_exclusion(self):
        response = self.client.get(reverse("exports"))
        self.assertContains(response, "Write DNS zones to directory")
        self.assertNotContains(response, "Retry NAS update")
        self.assertNotContains(response, "dns_nas")
        self.publish()
        config = Configuration.load()
        response = self.client.get(reverse("exports"))
        self.assertNotContains(response, "Retry NAS update")
        self.assertEqual(self.client.post("/exports/retry-nas/").status_code, 404)
        archive = snapshot()
        for field in ("dns_nas_host", "dns_nas_user", "dns_nas_port", "dns_published_generation", "dns_content_hash"):
            self.assertNotIn(field, archive["configuration"])
        legacy = copy.deepcopy(archive)
        legacy["configuration"].update(
            dns_nas_host="retired.example.test", dns_nas_user="retired", dns_nas_port=2222,
        )
        restore(legacy, config.revision)
        self.assertEqual(snapshot()["configuration"], archive["configuration"] | {"revision": config.revision + 1})
        for field in ("dns_nas_host", "dns_nas_user", "dns_nas_port"):
            self.assertFalse(hasattr(Configuration.load(), field))
        self.assertEqual(Configuration.load().dns_published_generation, config.dns_published_generation)
        self.assertEqual(Configuration.load().soa_serial, config.soa_serial)
