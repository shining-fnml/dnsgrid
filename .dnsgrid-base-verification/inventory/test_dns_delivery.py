import copy
import fcntl
import json
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import connection
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse

from .archives import restore, snapshot, validate
from .dns_delivery import check_result, delivery_states, publish_and_deliver, retry_delivery
from .dns_publication import read_generation
from .exporters import publish_dns_zones
from .models import Configuration, Host, Site
from .services import save_host, update_settings


class DNSDeliveryTests(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        Configuration.objects.update(
            dns_export_directory=str(self.path), soa_serial=2026100800,
            dns_sftp_host="nas.example.test", dns_sftp_user="dns",
            dns_sftp_inbox="/inbox", dns_sftp_outbox="/outbox",
        )
        self.clock = patch("inventory.dns_serial.initial_serial", return_value=2026100800)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.send = patch("inventory.dns_delivery.dns_sftp.deliver", return_value=("delivered", "waiting"))
        self.deliver = self.send.start()
        self.addCleanup(self.send.stop)
        self.result = patch("inventory.dns_delivery.dns_sftp.read_result", return_value=("pending", "waiting"))
        self.receipt = self.result.start()
        self.addCleanup(self.result.stop)
        self.user = get_user_model().objects.create_user("operator", is_staff=True)
        self.client.force_login(self.user)

    def publish(self):
        return publish_and_deliver(str(Configuration.load().revision))

    def state(self):
        config = Configuration.load()
        path, manifest = read_generation(str(self.path), config.dns_published_generation)
        return path, manifest, json.loads((path / ".delivery.json").read_text())

    def test_delivery_is_private_persisted_pinned_and_republication_reuses_attempt(self):
        def send(config, path, manifest, delivery):
            attempt = json.loads((path / ".delivery.json").read_text())
            self.assertEqual(attempt["delivery"], delivery)
            self.assertEqual(attempt["status"], "inflight")
            self.assertTrue((path / ".pin").exists())
            return "delivered", "waiting"
        self.deliver.side_effect = send
        self.assertEqual(self.publish()[2], "delivered")
        path, manifest, attempt = self.state()
        raw = (path / "manifest.json").read_bytes()
        self.assertEqual(stat.S_IMODE((path / ".delivery.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((path / ".pin").stat().st_mode), 0o600)
        self.assertEqual(self.publish()[2], "delivered")
        self.deliver.assert_called_once()
        self.assertEqual(self.state()[2]["delivery"], attempt["delivery"])
        self.assertEqual((path / "manifest.json").read_bytes(), raw)
        self.assertEqual(Configuration.load().soa_serial, manifest["serial"])
        self.assertContains(self.client.get(reverse("exports")), "Controlla esito NAS")

    def test_timeout_receipt_retry_exact_generation_and_old_result_rejected(self):
        self.deliver.return_value = ("unconfirmed", "timeout")
        self.publish()
        path, manifest, attempt = self.state()
        self.assertTrue((path / ".pin").exists())
        original = (path / "manifest.json").read_bytes()
        save_host(Host(name="new", site_id=1, row=1, column=0), Configuration.load().revision)
        config = Configuration.load()
        retry_delivery(config.revision, manifest["generation"])
        latest = self.state()[2]
        self.assertNotEqual(latest["delivery"], attempt["delivery"])
        with self.assertRaisesMessage(ValidationError, "changed"):
            check_result(config.revision, manifest["generation"], attempt["delivery"])
        self.receipt.assert_not_called()
        self.receipt.return_value = ("installed", "installed")
        self.assertEqual(check_result(config.revision, manifest["generation"], latest["delivery"])[0], "installed")
        self.assertFalse((path / ".pin").exists())
        self.assertEqual((path / "manifest.json").read_bytes(), original)
        self.assertEqual(Configuration.load().soa_serial, config.soa_serial)

    def test_only_matching_valid_success_releases_pin(self):
        self.publish()
        path, manifest, attempt = self.state()
        for status in ("pending", "invalid", "failed"):
            self.receipt.return_value = (status, status)
            self.assertEqual(check_result(1, manifest["generation"], attempt["delivery"])[0], status)
            self.assertTrue((path / ".pin").exists())
        self.receipt.return_value = ("already_installed", "done")
        check_result(1, manifest["generation"], attempt["delivery"])
        self.assertFalse((path / ".pin").exists())
        self.deliver.reset_mock()
        self.publish()
        self.deliver.assert_not_called()

    def test_receipt_is_checked_on_demand_and_disabled_ui_retains_saved_state(self):
        self.publish()
        _, _, attempt = self.state()
        self.client.get(reverse("exports"))
        self.receipt.assert_not_called()
        Configuration.objects.update(dns_sftp_inbox="")
        response = self.client.get(reverse("exports"))
        self.assertContains(response, attempt["delivery"])
        self.assertContains(response, "delivered")
        self.assertNotContains(response, "<button>Controlla esito NAS</button>")

    def test_destination_changes_do_not_reuse_or_confirm_another_nas_attempt(self):
        sites = list(Site.objects.values("id", "name", "g", "dsm_ifname"))
        for field, value in (
            ("dns_sftp_host", "another.example.test"), ("dns_sftp_user", "other"),
            ("dns_sftp_port", 2222), ("dns_sftp_inbox", "/other-inbox"),
            ("dns_sftp_outbox", "/other-outbox"),
        ):
            for confirmed in (False, True):
                self.publish()
                path, manifest, attempt = self.state()
                if confirmed:
                    self.receipt.return_value = ("installed", "done")
                    check_result(Configuration.load().revision, manifest["generation"], attempt["delivery"])
                update_settings({field: value}, sites, Configuration.load().revision)
                with self.assertRaisesMessage(ValidationError, "destination changed"):
                    check_result(Configuration.load().revision, manifest["generation"], attempt["delivery"])
                self.deliver.reset_mock()
                self.publish()
                self.deliver.assert_called_once()
                latest = self.state()[2]
                self.assertNotEqual(attempt["target"], latest["target"])
                self.assertNotEqual(attempt["delivery"], latest["delivery"])
                self.assertTrue((path / ".pin").exists())
                self.receipt.return_value = ("pending", "waiting")
                # Restore this field so the next iteration always changes the target.
                original = {
                    "dns_sftp_host": "nas.example.test", "dns_sftp_user": "dns",
                    "dns_sftp_port": 22, "dns_sftp_inbox": "/inbox", "dns_sftp_outbox": "/outbox",
                }[field]
                update_settings({field: original}, sites, Configuration.load().revision)

    def test_auth_csrf_revision_and_generation_delivery_guards(self):
        self.publish()
        _, manifest, attempt = self.state()
        data = {"revision": 1, "generation": manifest["generation"], "delivery": attempt["delivery"]}
        for name in ("dns-deliver", "dns-retry-delivery", "dns-result"):
            url = reverse(name)
            self.assertEqual(self.client.get(url).status_code, 405)
            self.assertEqual(Client().post(url, data).status_code, 302)
            csrf = Client(enforce_csrf_checks=True)
            csrf.force_login(self.user)
            self.assertEqual(csrf.post(url, data).status_code, 403)
            self.user.is_staff = False
            self.user.save()
            self.assertEqual(self.client.post(url, data).status_code, 403)
            self.user.is_staff = True
            self.user.save()
        self.deliver.reset_mock()
        for name in ("dns-deliver", "dns-retry-delivery", "dns-result"):
            response = self.client.post(reverse(name), {**data, "revision": 2}, follow=True)
            self.assertContains(response, "Stale configuration revision")
        for changes in ({"generation": "../escape"}, {"delivery": "invalid"},
                        {"generation": "dnsgrid-2026100801"}):
            self.client.post(reverse("dns-result"), {**data, **changes})
        self.receipt.assert_not_called()
        self.deliver.assert_not_called()

    def test_partial_local_failure_suppresses_delivery_and_lock_serializes_actions(self):
        with patch("inventory.exporters.os.replace", side_effect=OSError("denied")):
            self.assertTrue(self.publish()[1])
        self.deliver.assert_not_called()
        self.publish()
        _, manifest, attempt = self.state()
        with open(self.path / ".dnsgrid-delivery.lock", "rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            for action in (lambda: self.publish(), lambda: retry_delivery(1, manifest["generation"]),
                           lambda: check_result(1, manifest["generation"], attempt["delivery"])):
                with self.assertRaisesMessage(ValidationError, "Another"):
                    action()

    def test_pin_prevents_pruning_until_installation_and_metadata_prunes_with_generation(self):
        self.publish()
        first, manifest, attempt = self.state()
        for serial in range(2026100801, 2026100810):
            Configuration.objects.update(soa_serial=serial)
            self.publish()
        Configuration.objects.update(soa_serial=2026100810)
        self.assertIn("retention", str(self.publish()[1]))
        self.assertTrue(first.exists())
        self.receipt.return_value = ("installed", "done")
        check_result(1, manifest["generation"], attempt["delivery"])
        self.assertFalse((first / ".pin").exists())
        self.assertEqual(self.publish()[1], [])
        self.assertFalse(first.exists())
        self.assertEqual(len(delivery_states(Configuration.load())), 10)

    def test_failed_preparation_pins_without_network_and_corrupted_metadata_blocks_retry(self):
        with patch("inventory.dns_delivery._save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.publish()
        self.deliver.assert_not_called()
        generation = "dnsgrid-2026100800"
        path = self.path / "generations" / generation
        self.assertTrue((path / ".pin").exists())
        self.publish()
        (path / ".delivery.json").write_text("{}")
        with self.assertRaisesMessage(ValidationError, "metadata"):
            retry_delivery(1, generation)

    def test_local_only_disabled_and_archive_settings_excluded_preserved(self):
        publish_dns_zones("1")
        self.deliver.assert_not_called()
        data = snapshot()
        for field in ("dns_sftp_host", "dns_sftp_user", "dns_sftp_port", "dns_sftp_inbox", "dns_sftp_outbox"):
            self.assertNotIn(field, data["configuration"])
        legacy = copy.deepcopy(data)
        legacy["configuration"].update(dns_nas_host="retired", dns_nas_user="old", dns_nas_port=22)
        self.assertEqual(validate(legacy), data)
        restore(legacy, 1)
        self.assertEqual(Configuration.load().dns_sftp_host, "nas.example.test")
        Configuration.objects.update(dns_sftp_inbox="")
        self.assertEqual(self.publish()[2], "disabled")
        self.deliver.assert_not_called()

    def test_destination_validation_rejects_injection_and_blank_paths_disable(self):
        sites = list(Site.objects.values("id", "name", "g", "dsm_ifname"))
        for fields in ({"dns_sftp_host": "-oEvil"}, {"dns_sftp_user": "root;evil"},
                       {"dns_sftp_port": 0}, {"dns_sftp_inbox": "/a/../b"},
                       {"dns_sftp_outbox": "/a\nb"}):
            with self.assertRaises(ValidationError):
                update_settings(fields, sites, 1)
        response = self.client.get(reverse("configuration"))
        self.assertContains(response, "dns_sftp_inbox")
        self.assertNotContains(response, "DNSGRID_DNS_SFTP_IDENTITY_FILE")


class DNSDeliveryTransactionTests(TransactionTestCase):
    def test_sftp_runs_after_commit_and_inventory_can_change_during_network(self):
        Configuration.load()
        for index in range(1, 5):
            Site.objects.update_or_create(pk=index, defaults={"name": f"Site{index}", "g": index})
        with tempfile.TemporaryDirectory() as directory:
            Configuration.objects.update(
                dns_export_directory=directory, soa_serial=2026100800,
                dns_sftp_host="nas.example.test", dns_sftp_user="dns",
                dns_sftp_inbox="/inbox", dns_sftp_outbox="/outbox",
            )
            def send(config, path, manifest, delivery):
                self.assertFalse(connection.in_atomic_block)
                self.assertTrue((path / ".pin").exists())
                self.assertEqual(json.loads((path / ".delivery.json").read_text())["delivery"], delivery)
                save_host(Host(name="concurrent", site_id=1, row=1, column=0), config.revision)
                return "delivered", "waiting"
            with patch("inventory.dns_serial.initial_serial", return_value=2026100800):
                with patch("inventory.dns_delivery.dns_sftp.deliver", side_effect=send):
                    self.assertEqual(publish_and_deliver("1")[2], "delivered")
            self.assertEqual(Configuration.load().revision, 2)
            self.assertEqual(Configuration.load().soa_serial, 2026100801)

            config = Configuration.load()
            path, manifest = read_generation(directory, config.dns_published_generation)
            attempt = json.loads((path / ".delivery.json").read_text())
            def receipt(*args):
                self.assertFalse(connection.in_atomic_block)
                self.assertTrue((path / ".pin").exists())
                save_host(Host(name="during-check", site_id=1, row=2, column=0), config.revision)
                return "installed", "done"
            with patch("inventory.dns_serial.initial_serial", return_value=2026100800):
                with patch("inventory.dns_delivery.dns_sftp.read_result", side_effect=receipt):
                    self.assertEqual(check_result(config.revision, manifest["generation"], attempt["delivery"])[0], "installed")
            self.assertEqual(Configuration.load().revision, 3)
            self.assertFalse((path / ".pin").exists())
