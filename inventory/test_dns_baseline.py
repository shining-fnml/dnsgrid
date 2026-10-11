import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from .dns_serial import MAX_SERIAL, content_fingerprint
from .models import Configuration, Host, Site
from .services import lower_dns_serial


class DNSBaselineTests(TestCase):
    legacy = 2026100800
    baseline = 1791417600

    def setUp(self):
        self.clock = patch("inventory.dns_serial.initial_serial", return_value=self.baseline)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.service_clock = patch("inventory.services.initial_serial", return_value=self.baseline)
        self.service_clock.start()
        self.addCleanup(self.service_clock.stop)
        Configuration.load()
        Configuration.objects.update(soa_serial=self.legacy)
        self.admin = get_user_model().objects.create_user(
            username="baseline-admin", is_staff=True, is_superuser=True,
        )
        self.operator = get_user_model().objects.create_user(
            username="baseline-operator", is_staff=True,
        )
        self.client.force_login(self.admin)

    def preview(self, **extra):
        return self.client.post(reverse("dns-baseline-preview"), {
            "revision": Configuration.load().revision, **extra,
        })

    def confirm(self, **extra):
        pending = self.client.session.get("pending", {})
        return self.client.post(reverse("confirm"), {
            "nonce": pending.get("nonce", ""),
            "dns_unloaded_ack": "yes", "delivery_cleanup_ack": "yes", **extra,
        })

    def lower(self, **extra):
        return lower_dns_serial(**{
            "expected_revision": Configuration.load().revision,
            "expected_serial": self.legacy, "baseline": self.baseline,
            "confirmed": True, **extra,
        })

    def test_service_requires_confirmation_valid_bounds_and_exact_preview(self):
        for extra in (
            {"confirmed": False}, {"baseline": True}, {"baseline": -1},
            {"baseline": MAX_SERIAL + 1}, {"baseline": self.legacy},
            {"baseline": self.legacy + 1}, {"baseline": self.baseline + 1},
            {"expected_serial": self.legacy - 1}, {"expected_revision": 2},
        ):
            with self.subTest(extra=extra):
                before = list(Configuration.objects.values())
                with self.assertRaises(ValidationError):
                    self.lower(**extra)
                self.assertEqual(list(Configuration.objects.values()), before)

    def test_lowering_preserves_inventory_installer_state_and_immutable_generations(self):
        directory = tempfile.TemporaryDirectory(dir=Path.cwd(), prefix=".baseline-fixture-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        generation = root / "generations" / f"dnsgrid-{self.legacy}"
        generation.mkdir(parents=True)
        (generation / "forward.zone").write_bytes(b"legacy immutable generation")
        (root / "installer-state.json").write_bytes(b'{"serial":1692746706}')
        Configuration.objects.update(
            dns_export_directory=str(root),
            dns_published_generation=f"dnsgrid-{self.legacy}",
        )
        Host.objects.create(name="baseline-host", site_id=1, row=1, column=0)
        before_config = Configuration.objects.values().get(pk=1)
        before_hosts = list(Host.objects.values())
        before_sites = list(Site.objects.values())
        before_files = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        self.lower()
        config = Configuration.load()
        self.assertEqual(config.soa_serial, self.baseline)
        self.assertEqual(config.revision, before_config["revision"] + 1)
        self.assertEqual(config.dns_content_hash, content_fingerprint(config))
        self.assertEqual(config.dns_published_generation, "")
        for field, value in before_config.items():
            if field not in ("soa_serial", "revision", "dns_content_hash", "dns_published_generation"):
                self.assertEqual(getattr(config, field), value)
        self.assertEqual(list(Host.objects.values()), before_hosts)
        self.assertEqual(list(Site.objects.values()), before_sites)
        self.assertEqual(
            {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()},
            before_files,
        )

    def test_settings_button_and_preview_require_superuser(self):
        self.assertContains(self.client.get(reverse("configuration")), reverse("dns-baseline-preview"))
        self.client.force_login(self.operator)
        self.assertNotContains(self.client.get(reverse("configuration")), reverse("dns-baseline-preview"))
        self.assertEqual(self.preview().status_code, 403)
        self.client.logout()
        self.assertEqual(self.preview().status_code, 302)
        self.assertEqual(Configuration.load().soa_serial, self.legacy)

    def test_preview_is_post_only_server_chosen_and_displays_exact_values(self):
        self.assertEqual(self.client.get(reverse("dns-baseline-preview")).status_code, 405)
        response = self.preview(baseline=1, expected_serial=1)
        self.assertContains(response, str(self.legacy))
        self.assertContains(response, str(self.baseline))
        self.assertContains(response, 'name="dns_unloaded_ack"')
        self.assertContains(response, 'name="delivery_cleanup_ack"')
        self.assertContains(response, "No installer state is reset")
        self.assertEqual(self.client.session["pending"]["payload"], {
            "expected_serial": self.legacy, "baseline": self.baseline,
        })
        self.assertEqual(Configuration.load().soa_serial, self.legacy)
        self.confirm(baseline=1, expected_serial=1)
        self.assertEqual(Configuration.load().soa_serial, self.baseline)

    def test_each_acknowledgment_is_required_server_side_and_consumes_preview(self):
        for name in ("dns_unloaded_ack", "delivery_cleanup_ack"):
            with self.subTest(name=name):
                self.preview()
                response = self.confirm(**{name: ""})
                self.assertRedirects(response, reverse("configuration"))
                self.assertEqual(Configuration.load().soa_serial, self.legacy)
                self.assertNotIn("pending", self.client.session)

    def test_confirmation_checks_superuser_again(self):
        self.preview()
        self.admin.is_superuser = False
        self.admin.save(update_fields=["is_superuser"])
        self.assertEqual(self.confirm().status_code, 403)
        self.assertEqual(Configuration.load().soa_serial, self.legacy)

    def test_preview_rejects_stale_revision_invalid_revision_and_no_lowering(self):
        for revision in ("", "not-a-number", "2", "1" * 11):
            with self.subTest(revision=revision):
                self.assertRedirects(self.preview(revision=revision), reverse("configuration"))
                self.assertNotIn("pending", self.client.session)
        Configuration.objects.update(soa_serial=self.baseline)
        self.assertRedirects(self.preview(), reverse("configuration"))
        self.assertNotIn("pending", self.client.session)

    def test_confirmation_rejects_changed_revision_changed_serial_and_clock_rollback(self):
        for change in ("revision", "serial", "clock"):
            with self.subTest(change=change):
                Configuration.objects.update(revision=1, soa_serial=self.legacy)
                self.preview()
                if change == "revision":
                    Configuration.objects.update(revision=2)
                elif change == "serial":
                    Configuration.objects.update(soa_serial=self.legacy + 1)
                before = list(Configuration.objects.values())
                now = self.baseline - 1 if change == "clock" else self.baseline
                with patch("inventory.services.initial_serial", return_value=now):
                    self.confirm()
                self.assertEqual(list(Configuration.objects.values()), before)
                self.assertNotIn("pending", self.client.session)

    def test_wrong_nonce_and_replay_cannot_apply(self):
        self.preview()
        pending = self.client.session["pending"]
        self.confirm(nonce="wrong")
        self.assertEqual(Configuration.load().soa_serial, self.legacy)
        self.assertNotIn("pending", self.client.session)
        self.confirm(nonce=pending["nonce"])
        self.assertEqual(Configuration.load().soa_serial, self.legacy)
        self.preview()
        nonce = self.client.session["pending"]["nonce"]
        self.confirm()
        before = list(Configuration.objects.values())
        self.confirm(nonce=nonce)
        self.assertEqual(list(Configuration.objects.values()), before)

    def test_normal_settings_preview_uses_rfc1982_serial_ordering(self):
        for current, candidate, valid in (
            (1, 2147483649, False),
            (1, 2147483650, False),
            (MAX_SERIAL, 0, True),
        ):
            with self.subTest(current=current, candidate=candidate):
                Configuration.objects.update(soa_serial=current)
                response = self.client.get(reverse("configuration"))
                form = response.context["form"]
                data = {name: form[name].value() for name in form.fields}
                data.update(soa_serial=candidate, gandi_token="", clear_token="")
                response = self.client.post(reverse("configuration"), data)
                self.assertTemplateUsed(
                    response, "inventory/confirm.html" if valid else "inventory/form.html",
                )
                self.assertEqual(Configuration.load().soa_serial, current)
