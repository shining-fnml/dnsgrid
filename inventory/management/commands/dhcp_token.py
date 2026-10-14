from django.core.management.base import BaseCommand, CommandError

from inventory.dhcp import rotate_token
from inventory.models import Site


class Command(BaseCommand):
    help = ("Rotate a site's DHCP machine token (printed once), or revoke it with --revoke. "
            "Only a SHA256 verifier is stored; rotation invalidates the previous token.")

    def add_arguments(self, parser):
        parser.add_argument("site_id", type=int)
        parser.add_argument("--revoke", action="store_true")

    def handle(self, *args, **options):
        try:
            token = rotate_token(options["site_id"], revoke=options["revoke"])
        except Site.DoesNotExist as error:
            raise CommandError("Unknown site.") from error
        self.stdout.write(token if token else "Token revoked.")
