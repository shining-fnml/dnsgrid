from datetime import date, datetime, timezone
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .archives import dumps, restore, snapshot
from .exporters import build_exports
from .gandi_credentials import credential_summary, expiry_status
from .models import Configuration, Site
from .services import update_settings
from .views import CONFIG_FIELDS


class GandiExpirySettingsTests(TestCase):
    def setUp(self):
        self.environment = patch.dict("os.environ", {
            "DNSGRID_GANDI_TOKEN": "", "DNSGRID_GANDI_TOKEN_EXPIRES_ON": "",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.user = get_user_model().objects.create_user(username="operator", is_staff=True)
        self.client.force_login(self.user)
        self.config = Configuration.load()
        self.config.gandi_token = "fictitious-saved-pat"
        self.config.gandi_token_expires_on = date(2030, 6, 1)
        self.config.save()

    def settings_data(self, **changes):
        config = Configuration.load()
        data = {field: getattr(config, field) for field in CONFIG_FIELDS}
        data.update(revision=config.revision, soa_serial=config.soa_serial)
        for site in Site.objects.all():
            for field in ("name", "g", "dsm_ifname"):
                data[f"site_{site.pk}_{field}"] = getattr(site, field)
        data.update(changes)
        return data

    def confirm(self):
        return self.client.post(reverse("confirm"), {
            "nonce": self.client.session["pending"]["nonce"],
        })

    def update(self, **changes):
        response = self.client.post(reverse("configuration"), self.settings_data(**changes))
        self.assertTemplateUsed(response, "inventory/confirm.html")
        self.assertNotContains(response, self.config.gandi_token)
        self.assertNotContains(response, changes.get("gandi_token") or self.config.gandi_token)
        self.assertEqual(Configuration.load().revision, self.config.revision)
        self.assertEqual(self.confirm().status_code, 302)
        self.config.refresh_from_db()
        return response

    def test_keep_saved_token_and_date_is_noop(self):
        revision = self.config.revision
        self.update(gandi_token="")
        self.assertEqual(self.config.gandi_token_expires_on, date(2030, 6, 1))
        self.assertEqual(self.config.revision, revision)

    def test_replacement_without_date_resets_old_date(self):
        self.update(gandi_token="fictitious-replacement-pat")
        self.assertEqual(self.config.gandi_token, "fictitious-replacement-pat")
        self.assertIsNone(self.config.gandi_token_expires_on)

    def test_replacement_with_date_and_warning_uses_confirmation(self):
        revision, serial = self.config.revision, self.config.soa_serial
        response = self.update(
            gandi_token="fictitious-replacement-pat", gandi_token_expires_on="2031-04-05",
            gandi_token_warning_days=60,
        )
        self.assertContains(response, "Saved Gandi token expiration")
        self.assertEqual(self.config.gandi_token_expires_on, date(2031, 4, 5))
        self.assertEqual(self.config.gandi_token_warning_days, 60)
        self.assertEqual(self.config.revision, revision + 1)
        self.assertEqual(self.config.soa_serial, serial)

    def test_existing_date_can_be_updated_or_explicitly_removed(self):
        self.update(gandi_token_expires_on="2032-01-02")
        self.assertEqual(self.config.gandi_token_expires_on, date(2032, 1, 2))
        self.update(clear_token_expiry=True)
        self.assertIsNone(self.config.gandi_token_expires_on)
        self.assertEqual(self.config.gandi_token, "fictitious-saved-pat")

    def test_token_removal_also_removes_its_date(self):
        self.update(clear_token=True)
        self.assertEqual(self.config.gandi_token, "")
        self.assertIsNone(self.config.gandi_token_expires_on)

    def test_invalid_and_conflicting_inputs_do_not_echo_new_secret(self):
        cases = (
            {"clear_token": True, "gandi_token": "fictitious-new-pat"},
            {"clear_token": True, "gandi_token_expires_on": "2031-01-01"},
            {"clear_token_expiry": True, "gandi_token_expires_on": "2031-01-01"},
            {"gandi_token_expires_on": "2031-02-30"},
            {"gandi_token_warning_days": -1},
            {"gandi_token_warning_days": 3651},
            {"gandi_token_warning_days": "not-a-number"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                data = self.settings_data(gandi_token="fictitious-new-pat")
                data.update(changes)
                response = self.client.post(reverse("configuration"), data)
                self.assertTemplateUsed(response, "inventory/form.html")
                self.assertTrue(response.context["form"].errors)
                self.assertNotContains(response, "fictitious-new-pat")
                self.assertNotContains(response, self.config.gandi_token)
                self.assertEqual(Configuration.load().revision, self.config.revision)

    def test_warning_threshold_includes_zero_and_maximum(self):
        for days in (0, 3650):
            self.update(gandi_token_warning_days=days)
            self.assertEqual(self.config.gandi_token_warning_days, days)

    def test_stale_preview_and_confirmation_cannot_change_expiry(self):
        data = self.settings_data(gandi_token_expires_on="2031-01-01")
        data["revision"] -= 1
        response = self.client.post(reverse("configuration"), data)
        self.assertTemplateUsed(response, "inventory/form.html")
        response = self.client.post(reverse("configuration"), self.settings_data(
            gandi_token_expires_on="2031-01-01",
        ))
        self.assertTemplateUsed(response, "inventory/confirm.html")
        Configuration.objects.filter(pk=1).update(revision=self.config.revision + 1)
        self.confirm()
        self.assertEqual(Configuration.load().gandi_token_expires_on, date(2030, 6, 1))

    def test_settings_and_confirmation_require_staff(self):
        self.client.post(reverse("configuration"), self.settings_data(clear_token=True))
        nonce = self.client.session["pending"]["nonce"]
        self.user.is_staff = False
        self.user.save()
        for url, data in (
            ("configuration", self.settings_data(clear_token=True)), ("confirm", {"nonce": nonce}),
        ):
            self.assertEqual(self.client.post(reverse(url), data).status_code, 403)
        self.assertEqual(Client().get(reverse("configuration")).status_code, 302)
        self.assertEqual(Configuration.load().gandi_token, self.config.gandi_token)

    def test_service_resets_unspecified_expiry_on_replacement_and_clear(self):
        sites = list(Site.objects.values("id", "name", "g", "dsm_ifname"))
        for token in ("fictitious-service-pat", ""):
            self.config.gandi_token_expires_on = date(2030, 6, 1)
            self.config.save()
            result = update_settings({"gandi_token": token}, sites, self.config.revision)
            self.assertIsNone(result.gandi_token_expires_on)
            self.config = result

    def test_service_validates_warning_bounds_and_date_requires_saved_token(self):
        sites = list(Site.objects.values("id", "name", "g", "dsm_ifname"))
        for value in (-1, 3651):
            with self.assertRaises(ValidationError):
                update_settings({"gandi_token_warning_days": value}, sites, self.config.revision)
        self.config.gandi_token = ""
        with self.assertRaises(ValidationError):
            self.config.full_clean()

    def test_metadata_and_secrets_stay_out_of_archives_and_exports(self):
        archive = snapshot()
        text = dumps(archive)
        for value in (
            self.config.gandi_token, "gandi_token_expires_on", "gandi_token_warning_days",
        ):
            self.assertNotIn(value, text)
            self.assertNotIn(value, str(build_exports()))
        restore(archive, self.config.revision)
        current = Configuration.load()
        self.assertEqual(current.gandi_token_expires_on, self.config.gandi_token_expires_on)
        self.assertEqual(current.gandi_token_warning_days, self.config.gandi_token_warning_days)
        self.assertEqual(current.gandi_token, self.config.gandi_token)

    @override_settings(TIME_ZONE="Pacific/Honolulu")
    def test_operator_pages_show_active_source_and_utc_expiry_state(self):
        with patch("inventory.gandi_credentials.datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2030, 5, 2, 0, 0, tzinfo=timezone.utc)
            for url in ("grid", "configuration", "exports", "host-create", "vpn-report"):
                response = self.client.get(reverse(url))
                self.assertContains(response, "Gandi PAT (database)")
                self.assertContains(response, "expiring; declared expiration 2030-06-01")
                self.assertNotContains(response, self.config.gandi_token)
        with patch.dict("os.environ", {"DNSGRID_GANDI_TOKEN": "fictitious-environment-pat"}):
            response = self.client.get(reverse("configuration"))
            self.assertContains(response, "Gandi PAT (environment)")
            self.assertContains(response, "expiration unknown")
            self.assertNotContains(response, "fictitious-environment-pat")
            self.assertNotContains(response, 'name="gandi_token_expires_on" value=')
        self.assertNotContains(Client().get(reverse("login")), "Gandi PAT")
        self.user.is_staff = False
        self.user.save()
        self.assertNotContains(self.client.get(reverse("login")), "Gandi PAT")

    def test_all_states_and_inclusive_warning_and_expiry_day(self):
        today = date(2030, 5, 2)
        for expiry, days, expected in (
            (None, 30, "unknown"),
            (date(2030, 6, 2), 30, "valid"),
            (date(2030, 6, 1), 30, "expiring"),
            (date(2030, 5, 3), 0, "valid"),
            (today, 0, "expired"),
            (date(2030, 5, 1), 30, "expired"),
        ):
            with self.subTest(expiry=expiry, days=days):
                self.assertEqual(expiry_status(expiry, days, today=today), expected)
        for value in ("not-a-date", "2030-02-30", "20300502"):
            with patch.dict("os.environ", {
                "DNSGRID_GANDI_TOKEN": "fictitious-env-pat",
                "DNSGRID_GANDI_TOKEN_EXPIRES_ON": value,
            }):
                self.assertEqual(credential_summary(self.config)["status"], "unavailable")
