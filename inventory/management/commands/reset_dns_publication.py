from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from inventory import dns_reset


class Command(BaseCommand):
    help = "Preview or explicitly reset LOCAL test DNS publication history; never modifies the NAS."

    def add_arguments(self, parser):
        parser.add_argument("--confirm", action="store_true", help="Execute the destructive local reset.")
        parser.add_argument("--timestamp", type=int, help="Exact Unix-second serial shown in the preview.")
        parser.add_argument("--preview-token", help="Exact artifact/configuration token shown in the preview.")
        parser.add_argument("--ack-never-loaded", action="store_true",
                            help="Acknowledge legacy serials were NEVER loaded by any DNS server.")
        parser.add_argument("--ack-nas-handled", action="store_true",
                            help="Acknowledge DSM scheduling and stale test deliveries have been handled.")
        parser.add_argument("--recover", action="store_true", help="Resume the outstanding reset, rolling forward.")

    def handle(self, *args, **options):
        try:
            if options["confirm"] or options["recover"]:
                if not options["recover"] and options["timestamp"] is None:
                    raise ValidationError("An exact preview timestamp and token are required.")
                quarantine = dns_reset.reset(
                    options["timestamp"], options["preview_token"],
                    confirmed=options["confirm"], unloaded=options["ack_never_loaded"],
                    nas_handled=options["ack_nas_handled"], recover=options["recover"],
                )
                if quarantine is None:
                    self.stdout.write("No outstanding local reset; nothing changed.")
                else:
                    self.stdout.write(f"Local reset complete. Managed artifacts invalidated in quarantine: {quarantine}")
                    self.stdout.write("Publication reference cleared; content tracking reset. Inventory and revision counters unchanged.")
            else:
                plan, token = dns_reset.preview(options["timestamp"])
                self.stdout.write("READ-ONLY PREVIEW: no files or database values changed.")
                self.stdout.write(f"Export directory: {plan['directory']}")
                self.stdout.write(f"Local SOA serial: {plan['old_serial']} -> {plan['timestamp']} (Unix seconds)")
                for name, files in plan["artifacts"].items():
                    self.stdout.write(f"Quarantine: {plan['directory']}/{name}")
                    if name.startswith("generations/"):
                        for child in files:
                            self.stdout.write(f"  {plan['directory']}/{name}/{child}")
                    else:
                        self.stdout.write("  Known managed loose publication artifact (may be legacy).")
                self.stdout.write(
                    "To execute within 15 minutes, review the artifacts and use:\n"
                    f"python manage.py reset_dns_publication --confirm --timestamp {plan['timestamp']} "
                    f"--preview-token {token} --ack-never-loaded --ack-nas-handled"
                )
            self.stdout.write(
                "NAS files/state, backups, lock files, unrelated files, inventory, users, settings and credentials are not reset. "
                "This command does not prove what DNS servers have loaded."
            )
        except (ValidationError, OSError, DatabaseError) as error:
            raise CommandError(
                f"{error} If a reset journal exists, preserve it and its quarantine; "
                "resolve the error and use --recover --confirm with both acknowledgements. Never delete lock files."
            ) from error
