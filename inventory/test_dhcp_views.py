import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client, TestCase
from django.urls import reverse

from .dhcp import checksum, rotate_token
from .models import Configuration, DHCPPublication, Host, Site


class DHCPOperatorTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="operator", is_staff=True)
        self.client.force_login(self.user)
        self.config = Configuration.load()
        self.rows = [{
            "site_id": 2, "site_name": "DHCP site", "subnet": "192.168.4.0/24",
            "payload": {"ifname": "ovs_eth0", "reservationData": []},
            "sha256": "a" * 64, "destructive": True, "previous_version": "",
        }]

    @patch("inventory.dhcp_views.dhcp.preview")
    @patch("inventory.dhcp_views.dhcp.publish")
    def test_preview_requires_separate_confirmation_and_exact_nonce(self, publish, preview):
        preview.return_value = self.rows
        response = self.client.post(reverse("dhcp-preview"), {"revision": self.config.revision})
        self.assertContains(response, "Empty authoritative list")
        self.assertContains(response, "Explicit destructive authorization is required")
        self.assertContains(response, "CCD warnings remain advisory")
        publish.assert_not_called()
        pending = self.client.session["dhcp_preview"]
        self.client.post(reverse("dhcp-publish"), {"nonce": "wrong"})
        publish.assert_not_called()
        self.client.post(reverse("dhcp-publish"), {"nonce": "invalid-\N{SNOWMAN}"})
        publish.assert_not_called()
        self.client.post(reverse("dhcp-publish"), {
            "nonce": pending["nonce"], "authorize_destructive": "yes",
        })
        publish.assert_called_once_with(
            self.config.revision, self.rows, authorize_destructive=True,
        )
        self.assertNotIn("dhcp_preview", self.client.session)
        self.config.refresh_from_db()
        self.assertEqual(self.config.revision, 1)

    @patch("inventory.dhcp_views.dhcp.preview")
    @patch("inventory.dhcp_views.dhcp.publish")
    def test_publication_validation_failure_preserves_preview(self, publish, preview):
        preview.return_value = self.rows
        self.client.post(reverse("dhcp-preview"), {"revision": self.config.revision})
        pending = self.client.session["dhcp_preview"]
        publish.side_effect = ValidationError("Stale preview.")
        response = self.client.post(reverse("dhcp-publish"), {"nonce": pending["nonce"]})
        self.assertRedirects(response, reverse("dhcp-status"), fetch_redirect_response=False)
        self.assertEqual(self.client.session["dhcp_preview"], pending)

    def test_staff_only_and_post_only_actions(self):
        self.assertEqual(self.client.get(reverse("dhcp-preview")).status_code, 405)
        self.assertEqual(self.client.get(reverse("dhcp-publish")).status_code, 405)
        self.user.is_staff = False
        self.user.save()
        for route in ("dhcp-preview", "dhcp-publish", "dhcp-status"):
            self.assertEqual(self.client.post(reverse(route)).status_code, 403)

    def test_ordinary_operator_posts_keep_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        for route in ("dhcp-preview", "dhcp-publish"):
            self.assertEqual(client.post(reverse(route), {"revision": 1}).status_code, 403)

    @patch("inventory.dhcp_views.dhcp.status_rows")
    def test_status_is_read_only_and_distinguishes_missing_states(self, rows):
        rows.return_value = [{
            "site": {"name": "DHCP site", "pk": 2, "dsm_ifname": "ovs_eth0"},
            "subnet": "192.168.4.0/24", "status": "No publication",
            "pending": True, "history": [],
        }]
        response = self.client.get(reverse("dhcp-status"))
        self.assertContains(response, "No publication")
        self.assertContains(response, "No contact")
        self.assertContains(response, "No download")
        self.assertContains(response, "Unreported")
        self.assertContains(response, "Unpublished inventory changes")
        self.assertContains(response, "not independent proof")

    @patch("inventory.dhcp_views.dhcp.preview")
    def test_bad_revision_or_validation_never_stores_confirmation(self, preview):
        self.client.post(reverse("dhcp-preview"), {"revision": "not-an-integer"})
        preview.assert_not_called()
        self.assertNotIn("dhcp_preview", self.client.session)
        preview.side_effect = ValidationError("Invalid interface.")
        self.client.post(reverse("dhcp-preview"), {"revision": 1})
        self.assertNotIn("dhcp_preview", self.client.session)

    def test_published_manual_download_is_immutable_site_scoped_and_staff_only(self):
        payload = self.rows[0]["payload"]
        publication = DHCPPublication.objects.create(
            site_id=2, subnet=self.rows[0]["subnet"], payload=payload,
            sha256=checksum(payload), destructive_authorized=True,
        )
        url = reverse("dhcp-publication-download", args=[2, publication.pk])
        response = self.client.get(url)
        self.assertEqual(response.json(), payload)
        self.assertEqual(response["X-DNSGrid-Version"], publication.version)
        self.assertIn("no-cache", response["Cache-Control"])
        self.assertEqual(self.client.get(reverse(
            "dhcp-publication-download", args=[1, publication.pk],
        )).status_code, 404)
        self.user.is_staff = False
        self.user.save()
        self.assertEqual(self.client.get(url).status_code, 403)

    def test_operator_publish_machine_report_and_status_history_end_to_end(self):
        Site.objects.exclude(pk=2).update(dsm_ifname="")
        Site.objects.filter(pk=2).update(g=4, dsm_ifname="ovs_eth0")
        Host.objects.create(
            site_id=2, name="dhcp-host", row=1, column=0, mac="02:00:00:00:00:01",
        )
        token = rotate_token(2)
        self.client.post(reverse("dhcp-preview"), {"revision": self.config.revision})
        pending = self.client.session["dhcp_preview"]
        self.client.post(reverse("dhcp-publish"), {"nonce": pending["nonce"]})
        publication = DHCPPublication.objects.get(site_id=2)
        machine = Client(enforce_csrf_checks=True)
        headers = {"HTTP_AUTHORIZATION": "Bearer " + token}
        artifact = machine.get(reverse("dhcp-latest", args=[2]), **headers)
        self.assertEqual(artifact.status_code, 200)
        self.assertEqual(artifact.json()["subnet"], "192.168.4.0/24")
        response = machine.post(reverse("dhcp-result", args=[2]), {
            "schema_version": 1, "version": publication.version,
            "sha256": publication.sha256, "status": "applied",
        }, content_type="application/json", **headers)
        self.assertEqual(response.status_code, 200)
        response = self.client.get(reverse("dhcp-status"))
        self.assertContains(response, publication.version)
        self.assertContains(response, reverse(
            "dhcp-publication-download", args=[2, publication.pk],
        ))
        row = next(row for row in response.context["rows"] if row["site"].pk == 2)
        self.assertEqual(row["applied"].pk, publication.pk)
        self.assertIsNotNone(row["last_seen"])
        self.assertIsNotNone(row["last_downloaded_at"])
        self.assertFalse(row["pending"])
        self.assertEqual(row["status"], "applied")
        failure = {
            "schema_version": 1, "version": publication.version,
            "sha256": publication.sha256, "status": "failed",
            "diagnostic": "dsm_drift", "report_id": str(uuid.uuid4()),
        }
        result_url = reverse("dhcp-result", args=[2])
        self.assertEqual(machine.post(
            result_url, failure, content_type="application/json", **headers,
        ).status_code, 200)
        response = self.client.get(reverse("dhcp-status"))
        row = next(row for row in response.context["rows"] if row["site"].pk == 2)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(machine.post(result_url, {
            **failure, "status": "applied", "diagnostic": "", "report_id": str(uuid.uuid4()),
        }, content_type="application/json", **headers).status_code, 200)
        self.assertEqual(machine.post(
            result_url, failure, content_type="application/json", **headers,
        ).status_code, 200)
        response = self.client.get(reverse("dhcp-status"))
        row = next(row for row in response.context["rows"] if row["site"].pk == 2)
        self.assertEqual(row["status"], "applied")
        self.assertEqual(row["last_failure"].diagnostic, "dsm_drift")
