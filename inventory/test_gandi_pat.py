import os
from datetime import date, datetime, timezone
from unittest.mock import MagicMock, patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import Client, RequestFactory, TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from .exporters import build_exports
from .gandi import GandiClient, plan_sync, sync
from .gandi_api import pat
from .models import (
    Configuration, DHCPPublication, DHCPResult, DHCPState, GandiRecord, Host, Site,
)


class GandiPatTests(TestCase):
    database_token = "fictitious-database-pat"
    environment_token = "fictitious-environment-pat"
    today = date(2032, 6, 15)

    def setUp(self):
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        clock = patch("inventory.gandi_credentials.datetime")
        self.clock = clock.start()
        self.clock.now.return_value = datetime(2032, 6, 15, 23, 59, 59, tzinfo=timezone.utc)
        self.addCleanup(clock.stop)
        network = patch(
            "inventory.gandi.request.build_opener",
            side_effect=AssertionError("PAT retrieval must not contact Gandi"),
        )
        self.network = network.start()
        self.addCleanup(network.stop)
        self.config = Configuration.load()
        self.config.gandi_token = self.database_token
        self.config.gandi_token_expires_on = None
        self.config.save()
        self.host = Host.objects.create(
            name="pat-peer", site=Site.objects.get(pk=1), row=2, column=3,
            vpn=True, public_export=True,
        )
        self.peer = self.host.vpn_address(self.config)
        self.url = reverse("gandi-pat")

    def get(self, peer=None, **extra):
        return self.client.get(
            self.url, REMOTE_ADDR=self.peer if peer is None else peer, **extra,
        )

    def assert_private(self, response):
        self.assertEqual(response["Cache-Control"], "private, no-store")
        self.assertEqual(response["Pragma"], "no-cache")
        self.assertEqual(response["Expires"], "0")
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertNotIn("ETag", response)
        self.assertNotIn("Location", response)
        self.assertFalse(any(name.lower().startswith("access-control-")
                             for name in response.headers))

    def assert_success(self, response, token=None, expires_on=None):
        self.assertEqual(response.status_code, 200)
        self.assert_private(response)
        self.assertEqual(response.json(), {
            "token": self.database_token if token is None else token,
            "expires_on": expires_on,
        })
        self.assertLessEqual(len(response.content), 1100)

    def assert_error(self, response, status, error):
        self.assertEqual(response.status_code, status)
        self.assert_private(response)
        self.assertEqual(response.json(), {"error": error})
        self.assertLess(len(response.content), 100)
        for secret in (self.database_token, self.environment_token):
            self.assertNotIn(secret, response.content.decode())
            self.assertNotIn(secret, str(dict(response.headers)))

    def test_exact_computed_vpn_peer_is_allowed_without_login(self):
        self.assertEqual(self.peer, "172.28.1.50")
        self.assert_success(self.get())
        self.network.assert_not_called()

    def test_both_host_flags_are_required_and_changes_apply_immediately(self):
        for vpn, public in ((False, False), (False, True), (True, False)):
            with self.subTest(vpn=vpn, public_export=public):
                Host.objects.filter(pk=self.host.pk).update(vpn=vpn, public_export=public)
                self.assert_error(self.get(), 403, "unauthorized")
                Host.objects.filter(pk=self.host.pk).update(vpn=True, public_export=True)
                self.assert_success(self.get())

    def test_unknown_lan_and_outside_peers_are_denied(self):
        for peer in ("172.28.1.51", "172.28.2.50", "172.28.0.0",
                     self.host.lan_address(self.config), "203.0.113.50", "127.0.0.1"):
            with self.subTest(peer=peer):
                self.assert_error(self.get(peer), 403, "unauthorized")

    def test_malformed_noncanonical_and_ipv6_peers_are_denied(self):
        for peer in ("", "not-an-address", "::1", "2001:db8::1",
                     "::ffff:172.28.1.50", "::ffff:ac1c:132",
                     " 172.28.1.50", "172.28.1.50 ", "172.28.1.50\n",
                     "172.028.1.50", "172.28.01.50", "172.28.1.050",
                     "172.28.1.50:443", "172.28.1.50/32", "2887516466",
                     "172.28.1.50, 203.0.113.1", "172.28.1.256"):
            with self.subTest(peer=peer):
                self.assert_error(self.get(peer), 403, "unauthorized")

    def test_missing_or_nonstring_remote_addr_is_denied(self):
        for value in (None, 123, b"172.28.1.50"):
            with self.subTest(value=value):
                request = RequestFactory().get(self.url)
                if value is None:
                    request.META.pop("REMOTE_ADDR", None)
                else:
                    request.META["REMOTE_ADDR"] = value
                response = pat(request)
                self.assertEqual(response.status_code, 403)
                self.assert_private(response)
                self.assertEqual(response.content, b'{"error": "unauthorized"}')

    def test_query_parameters_are_ignored_for_authorization_and_credentials(self):
        query = {
            "ip": self.peer, "host": self.host.name, "REMOTE_ADDR": self.peer,
            "token": "fictitious-query-pat", "expires_on": "2099-01-01",
            "callback": "doNotUse", "format": "html",
        }
        self.assert_error(self.get("203.0.113.1", data=query), 403, "unauthorized")
        self.assert_success(self.get(data=query))

    def test_forwarded_headers_cannot_grant_or_replace_direct_peer(self):
        for header, value in (
            ("HTTP_X_FORWARDED_FOR", self.peer),
            ("HTTP_X_FORWARDED_FOR", f"{self.peer}, 203.0.113.1"),
            ("HTTP_X_REAL_IP", self.peer),
            ("HTTP_FORWARDED", f'for="{self.peer}";proto=https'),
            ("HTTP_CLIENT_IP", self.peer),
            ("HTTP_TRUE_CLIENT_IP", self.peer),
        ):
            with self.subTest(header=header, value=value):
                self.assert_error(self.get("203.0.113.1", **{header: value}),
                                  403, "unauthorized")
                self.assert_success(self.get(**{header: "203.0.113.1"}))

    def test_operator_and_superuser_have_no_authorization_bypass(self):
        user = get_user_model().objects.create_user(
            username="pat-operator", is_staff=True, is_superuser=True,
        )
        self.client.force_login(user)
        self.assert_error(self.get("203.0.113.1"), 403, "unauthorized")
        Host.objects.filter(pk=self.host.pk).update(public_export=False)
        self.assert_error(self.get(), 403, "unauthorized")

    def test_missing_configuration_fails_closed_without_creating_it(self):
        Configuration.objects.all().delete()
        with CaptureQueriesContext(connection) as queries:
            self.assert_error(self.get(), 503, "configuration_unavailable")
        self.assertFalse(Configuration.objects.exists())
        self.assert_no_writes(queries)

    def test_ambiguous_computed_peer_counts_disabled_matches_too(self):
        other = Host.objects.create(
            name="second-pat-peer", site=Site.objects.get(pk=2), row=3, column=3,
            vpn=True, public_export=True,
        )
        with patch.object(Host, "vpn_address", autospec=True, return_value=self.peer) as address:
            for vpn, public in ((True, True), (False, True), (True, False), (False, False)):
                with self.subTest(vpn=vpn, public_export=public):
                    Host.objects.filter(pk=other.pk).update(vpn=vpn, public_export=public)
                    address.reset_mock()
                    self.assert_error(self.get(), 403, "unauthorized")
                    self.assertEqual({call.args[0].pk for call in address.call_args_list},
                                     {self.host.pk, other.pk})

    def test_address_mapping_changes_are_read_on_every_request(self):
        self.assert_success(self.get())
        for model, pk, change in (
            (Host, self.host.pk, {"row": 3}),
            (Site, self.host.site_id, {"g": 42}),
            (Configuration, self.config.pk, {"vpn_prefix": "10.77"}),
        ):
            with self.subTest(change=change):
                previous = self.peer
                model.objects.filter(pk=pk).update(**change)
                self.config.refresh_from_db()
                self.host = Host.objects.select_related("site").get(pk=self.host.pk)
                self.peer = self.host.vpn_address(self.config)
                self.assertNotEqual(previous, self.peer)
                self.assert_error(self.get(previous), 403, "unauthorized")
                self.assert_success(self.get())
        self.host.delete()
        self.assert_error(self.get(), 403, "unauthorized")

    def test_environment_token_overrides_database_and_empty_or_absent_falls_back(self):
        for environment in ({}, {"DNSGRID_GANDI_TOKEN": ""},
                            {"DNSGRID_GANDI_TOKEN": self.environment_token}):
            with self.subTest(environment=environment), patch.dict(os.environ, environment, clear=True):
                self.assert_success(self.get(), token=environment.get("DNSGRID_GANDI_TOKEN")
                                    or self.database_token)

    def test_credential_changes_are_immediately_effective(self):
        self.assert_success(self.get())
        Configuration.objects.filter(pk=1).update(gandi_token="fictitious-replacement-pat")
        self.assert_success(self.get(), token="fictitious-replacement-pat")
        with patch.dict(os.environ, {"DNSGRID_GANDI_TOKEN": self.environment_token}):
            self.assert_success(self.get(), token=self.environment_token)
        self.assert_success(self.get(), token="fictitious-replacement-pat")

    def test_missing_credential_is_unavailable_but_environment_can_supply_it(self):
        Configuration.objects.filter(pk=1).update(gandi_token="")
        for environment in ({}, {"DNSGRID_GANDI_TOKEN": ""}):
            with self.subTest(environment=environment), patch.dict(os.environ, environment, clear=True):
                self.assert_error(self.get(), 503, "credential_unavailable")
        with patch.dict(os.environ, {"DNSGRID_GANDI_TOKEN": self.environment_token}):
            self.assert_success(self.get(), token=self.environment_token)

    def test_invalid_database_and_environment_tokens_fail_safely(self):
        invalid = (
            " ", "fictitious bad", " fictitious-leading", "fictitious-trailing ",
            "fictitious\tpat", "fictitious\npat", "fictitious\r\npat",
            "fictitious\x00pat", "fictitious\x1fpat", "fictitious\x7fpat",
            "fictitious-é-pat", "fictitious-\u2603-pat", "f" * 513,
        )
        for source in ("database", "environment"):
            for token in invalid:
                with self.subTest(source=source, token=repr(token)):
                    Configuration.objects.filter(pk=1).update(
                        gandi_token=token if source == "database" else self.database_token,
                    )
                    environment = {"DNSGRID_GANDI_TOKEN": token} if source == "environment" else {}
                    with patch("inventory.gandi_credentials.os.environ", environment):
                        response = self.get()
                    self.assert_error(response, 503, "credential_unavailable")
                    if token.strip():
                        self.assertNotIn(token, response.content.decode())

    def test_printable_ascii_token_boundaries_are_supported(self):
        for token in ("!", "~", "f" * 512, '"' * 512, "\\" * 512):
            with self.subTest(length=len(token)):
                Configuration.objects.filter(pk=1).update(gandi_token=token)
                self.assert_success(self.get(), token=token)

    def test_environment_token_does_not_inherit_database_expiry(self):
        Configuration.objects.filter(pk=1).update(gandi_token_expires_on=date(2000, 1, 1))
        self.assert_error(self.get(), 503, "credential_expired")
        with patch.dict(os.environ, {"DNSGRID_GANDI_TOKEN": self.environment_token}):
            self.assert_success(self.get(), token=self.environment_token)
        with patch.dict(os.environ, {
            "DNSGRID_GANDI_TOKEN": self.environment_token,
            "DNSGRID_GANDI_TOKEN_EXPIRES_ON": "",
        }):
            self.assert_success(self.get(), token=self.environment_token)

    def test_database_token_does_not_inherit_environment_expiry(self):
        Configuration.objects.filter(pk=1).update(gandi_token_expires_on=date(2032, 7, 1))
        for environment in (
            {"DNSGRID_GANDI_TOKEN_EXPIRES_ON": "2000-01-01"},
            {"DNSGRID_GANDI_TOKEN": "", "DNSGRID_GANDI_TOKEN_EXPIRES_ON": "invalid"},
        ):
            with self.subTest(environment=environment), patch.dict(os.environ, environment, clear=True):
                self.assert_success(self.get(), expires_on="2032-07-01")

    def test_environment_expiry_is_separate_metadata(self):
        with patch.dict(os.environ, {
            "DNSGRID_GANDI_TOKEN": self.environment_token,
            "DNSGRID_GANDI_TOKEN_EXPIRES_ON": "2032-07-01",
        }):
            self.assert_success(self.get(), token=self.environment_token, expires_on="2032-07-01")
        self.assert_success(self.get())

    def test_invalid_environment_expiry_fails_closed(self):
        for expiry in ("unknown", "2032-02-30", "2032-6-16", "20320616",
                       "2032-06-16T00:00:00Z", " 2032-06-16", "2032-06-16\n",
                       "0000-01-01", "2032-06-16\x00"):
            with self.subTest(expiry=repr(expiry)), patch("inventory.gandi_credentials.os.environ", {
                "DNSGRID_GANDI_TOKEN": self.environment_token,
                "DNSGRID_GANDI_TOKEN_EXPIRES_ON": expiry,
            }):
                self.assert_error(self.get(), 503, "credential_unavailable")

    def test_expiry_cutoff_is_inclusive_of_the_current_utc_day(self):
        for expiry, allowed in ((date(2032, 6, 14), False),
                                (self.today, False), (date(2032, 6, 16), True)):
            for source in ("database", "environment"):
                with self.subTest(expiry=expiry, source=source):
                    Configuration.objects.filter(pk=1).update(gandi_token_expires_on=expiry)
                    environment = {
                        "DNSGRID_GANDI_TOKEN": self.environment_token,
                        "DNSGRID_GANDI_TOKEN_EXPIRES_ON": expiry.isoformat(),
                    } if source == "environment" else {}
                    with patch.dict(os.environ, environment, clear=True):
                        response = self.get()
                    if allowed:
                        self.assert_success(
                            response, token=self.environment_token if environment else self.database_token,
                            expires_on=expiry.isoformat(),
                        )
                    else:
                        self.assert_error(response, 503, "credential_expired")
        self.assertTrue(self.clock.now.called)
        self.assertTrue(all(call.args == (timezone.utc,) for call in self.clock.now.call_args_list))

    def test_warning_window_does_not_prevent_disclosure_before_expiry(self):
        for warning_days in (0, 30, 3650):
            with self.subTest(warning_days=warning_days):
                Configuration.objects.filter(pk=1).update(
                    gandi_token_expires_on=date(2032, 6, 16),
                    gandi_token_warning_days=warning_days,
                )
                self.assert_success(self.get(), expires_on="2032-06-16")

    def test_expiry_metadata_does_not_disable_gandi_client_or_sync(self):
        for expiry in (None, date(2000, 1, 1)):
            with self.subTest(database_expiry=expiry):
                Configuration.objects.filter(pk=1).update(gandi_token_expires_on=expiry)
                self.assert_sync_with_mocked_network(self.database_token)
        for expiry in ("", "invalid", "2000-01-01"):
            with self.subTest(environment_expiry=expiry), patch.dict(os.environ, {
                "DNSGRID_GANDI_TOKEN": self.environment_token,
                "DNSGRID_GANDI_TOKEN_EXPIRES_ON": expiry,
            }):
                self.assert_sync_with_mocked_network(self.environment_token)

    def assert_sync_with_mocked_network(self, token):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"[]"
        with patch("inventory.gandi.request.build_opener") as opener:
            opener.return_value.open.return_value = response
            config = Configuration.objects.get(pk=1)
            self.assertEqual(GandiClient(config).token, token)
            plan = plan_sync(config=config, hosts=[])
            self.assertEqual(sync(config=config, hosts=[], expected_fingerprint=plan["fingerprint"]),
                             plan)
            self.assertTrue(opener.return_value.open.called)
            for call in opener.return_value.open.call_args_list:
                self.assertEqual(call.args[0].get_header("Authorization"), "Bearer " + token)

    def test_conditional_requests_never_return_304(self):
        for etag in ("*", '"fictitious-etag"'):
            with self.subTest(etag=etag):
                headers = {
                    "HTTP_IF_NONE_MATCH": etag,
                    "HTTP_IF_MODIFIED_SINCE": "Wed, 01 Jan 2098 00:00:00 GMT",
                    "HTTP_ORIGIN": "https://untrusted.example",
                }
                self.assert_success(self.get(**headers))
                self.assert_error(self.get("203.0.113.1", **headers), 403, "unauthorized")
                Configuration.objects.filter(pk=1).update(gandi_token="")
                self.assert_error(self.get(**headers), 503, "credential_unavailable")
                Configuration.objects.filter(pk=1).update(gandi_token=self.database_token)

    def test_get_is_the_only_allowed_method_including_head(self):
        for method in ("HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"):
            for peer in (self.peer, "203.0.113.1"):
                with self.subTest(method=method, peer=peer):
                    response = self.client.generic(
                        method, self.url, REMOTE_ADDR=peer,
                        HTTP_ORIGIN="https://untrusted.example",
                    )
                    self.assertEqual(response.status_code, 405)
                    self.assertEqual(response["Allow"], "GET")
                    self.assert_private(response)
                    if method == "HEAD":
                        self.assertEqual(response.content, b"")
                    else:
                        self.assert_error(response, 405, "method_not_allowed")

    def test_post_with_csrf_checks_still_returns_fixed_json_without_writes(self):
        client = Client(enforce_csrf_checks=True)
        before = self.snapshot()
        with CaptureQueriesContext(connection) as queries:
            for peer in (self.peer, "203.0.113.1"):
                with self.subTest(peer=peer):
                    response = client.post(
                        self.url, {"token": "fictitious-post-pat"}, REMOTE_ADDR=peer,
                    )
                    self.assert_error(response, 405, "method_not_allowed")
                    self.assertEqual(response["Allow"], "GET")
        self.assert_no_writes(queries)
        self.assertEqual(self.snapshot(), before)
        self.network.assert_not_called()

    def test_request_logging_does_not_disclose_fictitious_credentials(self):
        with self.assertLogs("django.request", level="WARNING") as logs:
            self.assert_error(self.get("203.0.113.1"), 403, "unauthorized")
            with patch.dict(os.environ, {"DNSGRID_GANDI_TOKEN": self.environment_token + "\n"}):
                self.assert_error(self.get(), 503, "credential_unavailable")
            Configuration.objects.filter(pk=1).update(gandi_token_expires_on=date(2000, 1, 1))
            self.assert_error(self.get(), 503, "credential_expired")
        for secret in (self.database_token, self.environment_token):
            self.assertNotIn(secret, "\n".join(logs.output))
        with self.assertNoLogs("django.request", level="DEBUG"):
            Configuration.objects.filter(pk=1).update(gandi_token_expires_on=None)
            self.assert_success(self.get())

    def snapshot(self):
        return {
            model._meta.label: list(model.objects.order_by("pk").values())
            for model in apps.get_models()
        }

    def assert_no_writes(self, queries):
        self.assertEqual([
            query["sql"] for query in queries
            if query["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "REPLACE"))
        ], [])

    def test_gets_do_not_change_any_model_revision_dhcp_ownership_or_exports(self):
        publication = DHCPPublication.objects.create(
            site=self.host.site, subnet="192.168.1.0/24",
            payload={"fictitious": "publication"}, sha256="a" * 64,
        )
        result = DHCPResult.objects.create(publication=publication, status="applied")
        DHCPState.objects.update_or_create(site=self.host.site, defaults={
            "latest": publication, "applied": publication, "downloaded": publication,
            "last_attempt": result, "applied_receipt": result, "token_sha256": "b" * 64,
        })
        GandiRecord.objects.create(
            zone=self.config.gandi_zone, name="fictitious-owned", values=["203.0.113.9"],
        )
        for token, expiry, status, error in (
            (self.database_token, None, 200, None),
            ("", None, 503, "credential_unavailable"),
            (self.database_token, date(2000, 1, 1), 503, "credential_expired"),
        ):
            with self.subTest(status=status, error=error):
                Configuration.objects.filter(pk=1).update(
                    gandi_token=token, gandi_token_expires_on=expiry,
                )
                before = self.snapshot(), build_exports()
                with CaptureQueriesContext(connection) as queries:
                    for _ in range(2):
                        response = self.get()
                        if status == 200:
                            self.assert_success(response)
                        else:
                            self.assert_error(response, status, error)
                        self.assert_error(self.get("203.0.113.1"), 403, "unauthorized")
                self.assert_no_writes(queries)
                self.assertEqual((self.snapshot(), build_exports()), before)
        self.network.assert_not_called()
