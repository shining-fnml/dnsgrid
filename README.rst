dnsgrid
=======

dnsgrid is built for my own infrastructure and reflects my grid, addressing
conventions, and host-management workflows. You are welcome to study it,
adapt it, or reuse parts of it under the GNU AGPL-3.0 license in ``LICENSE``.
It is not a universal network-management product.

The application has one global 16-row, 8-column grid, four geographic sites,
deterministic DNS/DHCP exports, explicit Gandi synchronization, and a
read-only VPN file report. Built with Python 3.12+ and Django, it uses SQLite
without a separate frontend build. It models inventory and intended
configuration, not network discovery or monitoring of connected clients.

How I use it
------------

This application manages inventory and publishes primary zones on the VPN
hub. The hub runs BIND, and NAS appliances on the physical LANs act as
secondaries. Network addresses in configuration examples are placeholders
and must be replaced with deployment values.

1. Configure the four sites in Settings. Their stable IDs are 1–4; each has
   a distinct third IPv4 octet ``g`` (initially 1–4). The grid is shared
   across sites, not four separate grids. Rows and columns are zero-based:
   ``x = 16 * column + row``, with (0, 0) reserved and x from 1 to 127.
   With the default prefixes, LAN addresses are ``192.168.g.x`` and VPN
   addresses are ``172.28.g.x``. For example, fictitious ``demo-node`` at
   row 2, column 3 in a site with g=1 has x=50, LAN ``192.168.1.50``,
   and VPN ``172.28.1.50``.
2. Enter hosts, their VPN membership, optional MACs, and public-export
   flags. LAN DNS covers all inventory hosts; DHCP reservations require a
   MAC. Status is descriptive and does not exclude hosts from exports.
   Review and confirm changes, including any shifted hosts and addresses.
3. Review Export previews. Explicit publication validates and installs the
   ``intranet.linuxcondom.net.`` and ``vpn.`` primary zones and generated LAN
   reverse zones on the hub. The NAS appliances are secondaries; LAN clients
   use their local NAS resolvers. Public Gandi records remain a separate,
   opt-in feature and are not involved in either private zone.
4. For Synology reservations, configure the site's DSM interface, download
   its JSON, and manually copy it and ``synology/dsm_apply.py`` to the
   target NAS. Preview there before explicitly applying the complete
   interface reservation list. Only this standalone NAS-side operation
   uses sudo; the web application does not apply DSM changes.
4. On the VPN hub, run the web app as an unprivileged service account with
   access to its local BIND zone directory and read access to the existing
   narrow ``/etc/hosts`` and ``/etc/openvpn/ccd`` report sources. dnsgrid no
   longer exports ``/etc/hosts``. The VPN report remains read-only; correct
   discrepancies manually.

The sections below describe confirmations, exports, and deployment details.
Before any visibility change, review `PUBLICATION.rst <PUBLICATION.rst>`_:
this preparation is not authorization to publish.

Quick start
-----------

Run these commands from the repository root as an unprivileged user, not
root (and do not use sudo for the web app)::

    python -m venv .venv
    . .venv/bin/activate
    python -m pip install -r requirements.txt
    python manage.py migrate
    python manage.py createsuperuser
    DNSGRID_DEBUG=1 python manage.py runserver 127.0.0.1:8000

Open http://127.0.0.1:8000 and sign in. Superusers are operators;
other accounts need Django's ``is_staff`` flag. There is no anonymous
inventory access or public signup. All mutations require POST and CSRF
protection. The application does not expose a Django admin route that
could bypass placement or revision rules.

For a persistent deployment set ``DNSGRID_SECRET_KEY`` to a securely
generated secret in your process environment. Without it, a new random
key is generated on each process startup: existing sessions are invalidated
and multiple workers cannot share sessions reliably. Never commit secrets.
Set ``DNSGRID_ALLOWED_HOSTS`` to a comma-separated hostname allowlist.
Leave ``DNSGRID_DEBUG`` unset in production unless temporarily collecting
terminal diagnostics with level 2 (described below). Never use level 1 in
production: it enables Django's web DEBUG mode.

Use a production WSGI/ASGI server with ``dnsgrid.wsgi:application`` or
``dnsgrid.asgi:application``, not Django's development server. Terminate
HTTPS at your web server and set ``DNSGRID_HTTPS=1`` for secure cookies and
HTTPS redirects. Run ``python manage.py collectstatic`` and serve
``staticfiles/`` at ``/static/`` from that web server. A reverse proxy must
preserve HTTPS information appropriately; do not trust client-supplied
forwarded headers. Django's deployment checklist applies.

If the owner later makes the repository public, the VPN hub can clone it
over HTTPS without repository credentials::

    git clone https://github.com/shining-fnml/dnsgrid.git
    cd dnsgrid
    git pull --ff-only

Anonymous HTTPS clone/pull applies only after publication; while private,
read access still requires authorization. Push always requires write
authorization, even for a public repository. Public source code does not
make the running application or its inventory public.

Inventory and confirmations
---------------------------

* The address index is ``x = 16 * column + row``. Cell (0, 0) is
  reserved; the other 127 positions are shared by all four sites.
* Click a free cell to insert, or an occupied cell to edit. To insert
  into an occupied position, use "Insert a new host here" in its editor.
  Consecutive occupants shift downward to the first free position in
  that column. A full tail is rejected atomically, without wraparound.
* Changing a host's site alone retains its position. Changing its row
  or column uses the same insertion rules. Deleting leaves a hole.
* The existing host editor offers "Move up" / "Move down" only when
  the adjacent x is free and within 1–127. These shortcuts act on the
  saved entry, ignoring unsaved edits, and change x by exactly -1 / +1,
  including across column boundaries (16 → 15 and 15 → 16). They preview
  old/new x and LAN/VPN addresses before confirmation, preserve all other
  host metadata, and never shift, swap, compact, or skip occupied cells.
* Preview and confirm host changes, deletions, and global settings.
  Diffs show affected addresses and metadata. Inventory revisions
  reject stale forms and stale confirmations; refresh and preview again.
* ``running``, ``decommissioned``, and ``unconfirmed`` are informational.
  Nothing expires automatically and statuses never enter exports.
* Occupied grid cells use dark ink by stable site ID: 1 blue, 2 green,
  3 red, 4 gold, independent of site names or subnet octets. Their surfaces
  stay light even in dark mode; the rest of the application retains its
  theme. VPN names are bold, and the VPN address is bold only when that
  host is also publicly exported. Unconfirmed cells are light gray, and
  decommissioned names appear as ``(name)`` only in the grid. Stored names,
  FQDNs, and exports are unchanged. The legend uses configured site names.
  Cells show no visible status/Public export row; a nonempty MAC appears
  as an optional final line.
* A small grid-only script translates the original table header as one
  unit to keep it visible during viewport vertical scrolling, preserving
  column alignment and the grid's native horizontal scrolling.
* Names are unique DNS labels. MACs accept colon, hyphen, dotted, or
  compact hexadecimal formats and normalize to lowercase colon form.
  A single terminal semicolon is accepted, with surrounding whitespace,
  for pasted DHCP-style values; it is removed before validation.
  Invalid, multicast, zero, or duplicate nonempty MACs are rejected.
* Column headings describe networking, peripherals, bare-metal and
  virtual servers, console/TV desktops, laptops, and phones. Hardware
  category remains independent, optional free-text descriptive metadata;
  it does not filter exports. The column already supplies the grid category.
  Removing this potentially redundant field is a separate follow-up, not
  a change to existing data or forms.

Global settings
---------------

The Settings page configures LAN/VPN domains, two-octet IPv4 prefixes,
the four site names and distinct third octets, ``ttl``, ``soa_ns``,
``soa_mailbox``, ``soa_refresh``, ``soa_retry``, ``soa_expire``,
``soa_minimum``, the separate zone-apex ``zone_ns``, the BIND zone directory,
absolute ``named_checkzone``/``rndc`` executable paths, the absolute
``rndc_key`` path, the Gandi zone, and an optional Gandi token. ``soa_ns`` is
the SOA primary nameserver; ``zone_ns`` supplies each zone's NS record. The
three BIND tool/key paths must be configured together and are not archived.
Each site also has an optional DSM DHCP interface name (for example
``ovs_eth0``). Set it to the interface serving that site's LAN subnet
on its DSM server; leaving it blank disables that site's DSM API exports.
The SOA mailbox is a DNS name such as ``hostmaster.example.tld``, not
an email address. Defaults derive ``192.168.g.x`` and ``172.28.g.x``.
The persisted SOA serial is separate from the optimistic inventory revision.
All zones share a Unix timestamp in seconds, an unsigned 32-bit integer
(``0..4294967295``), not a calendar date or ``YYYYMMDDnn`` counter.
DNS-changing service mutations compare deterministic zone contents excluding
the serial: host names/addresses, VPN membership, site subnets, domains, TTL,
SOA and NS changes advance it, but descriptive metadata, public-export/Gandi-only
settings and previews, downloads or unchanged republication do not. Allocation uses
``max(now, last + 1)``: same-second edits and clock rollback still advance.
The timestamp-based serial need not equal the exact wall-clock second:
rapid edits, clock rollback, or a previously seeded value can keep it ahead.
There is no daily limit. Exhausting uint32 rejects the mutation rather than
wrapping silently. Settings' ``soa_serial`` permits a uint32 seed that advances
under RFC 1982 serial arithmetic, including a numerically smaller value when
RFC 1982 wraparound makes it newer.
Comparisons separated by exactly ``2147483648`` are ambiguous and rejected;
numerically larger values are not necessarily newer under RFC 1982.

Migration preserves the larger of the timestamp baseline and the old revision.
Legacy archives without a serial follow the same rule; restore never regresses
the destination serial under RFC 1982 (numeric wraparound can still advance).
Higher legacy values are preserved, not rewritten
automatically. Archives now include
``soa_serial`` in JSON v1; older archive shapes remain accepted. Restore may
advance the serial when DNS content differs, independently of its revision.

Exceptional administrator-confirmed baseline lowering
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Only a superuser (``is_superuser``), not an ordinary staff operator, can
preview and confirm timestamp baseline lowering from Settings. It is for
legacy serials that **no DNS server has loaded**, not a way to downgrade
an installed zone. Compare the actual proposed baseline with the hub primary
and every secondary before changing it.

Before changing a legacy installation, stop the old DSM DNS installer task
and quarantine any queued legacy deliveries. Review the exact old/new serials
and confirm that no DNS server loaded the legacy serials.
The browser cannot choose an arbitrary baseline. Confirmation requires the
same inventory revision and current serial, and rejects a preview timestamp
that is now in the future after clock rollback. A nonce is single-use.

Back up first. No inventory is deleted, no server state is automatically
reset, and stale immutable generations are preserved. Never retry or deliver
legacy generations after lowering. Publish and validate a new generation
before updating secondaries. If any server has already loaded the legacy serial,
**do not lower**: coordinate a migration with authoritative and secondary DNS
servers, respecting RFC 1982, outside this exceptional web action.

Resetting LOCAL test publication history
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a clean restart when **all managed local generations are test material
that was NEVER loaded by any DNS server**, use the explicit management command
instead of manually removing generations, legacy receipt metadata or lock files.
The Settings baseline action above deliberately preserves immutable generations;
the command below invalidates them by moving them to private local quarantine.
It never contacts DNS servers and cannot establish what they actually loaded.

Before acknowledging the reset:

* Stop the retired DSM DNS installer task and any other legacy delivery triggers.
* Inspect actual served serials on the hub primary and secondaries. Do not
  automatically lower installed serials or erase server recovery state.
* Quarantine only known legacy test deliveries and matching receipts. Never
  delete an outstanding recovery journal or remove unrelated NAS files.
* Back up the local database and export artifacts. Use a dedicated local export
  directory with trusted ownership; stop external/manual writers during reset.
  This command coordinates dnsgrid writers, not arbitrary filesystem processes.

Run from the project directory using the same environment and account as dnsgrid::

    python manage.py reset_dns_publication

The default is read-only: it displays the configured export directory, the exact
old/new serial, every managed generation/file affected, known loose zone artifacts
and a preview token. It creates no lock file and changes no database values.
Review that list. The printed execution command requires ``--confirm``,
``--timestamp`` and ``--preview-token``, plus **both** noninteractive acknowledgments::

    python manage.py reset_dns_publication --confirm --timestamp <preview-seconds> \
        --preview-token <preview-token> --ack-never-loaded --ack-nas-handled

Do not supply those acknowledgments unless the conditions above are true.
The timestamp is the current Unix time in whole seconds captured in the preview,
not zero; previews expire after 15 minutes and reject clock rollback. Configuration,
inventory DNS content, serial and artifact changes invalidate the token. Lock
contention fails safely: wait for the actual operation to finish and retry; never
unlink a lock file. Application revision counters are preserved, not reset or
incremented; existing web baseline confirmations reject the changed serial.

Under the publication lock and singleton database write lock, the command validates
immutable manifests/checksums and legacy attempt metadata, rejects symlinks, hard links,
unexpected generation contents and unsafe paths, and moves only validated managed
artifacts into ``.dnsgrid-reset-<random-id>`` inside the export directory. It does
not recursively delete the export directory. Unrelated files remain; loose zone
filenames are handled only when known from current configuration, valid generations,
or historical ``forward.zone`` / ``reverse-<0..255>.zone`` names.
Malformed artifacts require administrator review/manual quarantine, not a force
flag. The quarantine includes pins and saved attempts, so old test generations
are no longer available to retry/reuse. Keep it as an audit/recovery record; do not
copy it back into ``generations``.

The database serial is set to the reviewed timestamp, the published-generation
reference is cleared, and content tracking is rebuilt from unchanged inventory.
Inventory, revision counters, users, settings, secrets, and unrelated
application archive backups are untouched. The next unchanged publication
creates a fresh timestamp generation.

Filesystem moves and the database commit cannot form one atomic transaction.
A durable ``.dnsgrid-reset.json`` records the exact plan, fingerprints and
quarantine before any move. While it exists, publication and
inventory/configuration mutations are blocked. On failure, **preserve the journal
and quarantine**, resolve the reported filesystem/database issue, and resume::

    python manage.py reset_dns_publication --recover --confirm \
        --ack-never-loaded --ack-nas-handled

Recovery validates the original plan, recognizes completed moves and a database
commit that already succeeded, and rolls forward; it never reactivates old attempts.
It refuses missing, changed, duplicated or malformed artifacts/configuration and
requires administrator investigation in those cases. Do not bypass that refusal by
deleting the journal or changing configuration directly. After commit the journal
is moved to ``completed.json`` in quarantine; repeating recovery is a no-op.
If a crash occurred before the journal was written, no managed artifacts were moved;
an empty quarantine may remain and can be reviewed separately.

Publish locally, inspect the new generation/serial, then verify the hub's
authoritative answer and secondary transfer separately. No external client
resolution is implied by a successful RNDC command.

``dns_export_directory`` is an optional absolute path to an existing BIND zone
directory on the hub. Blank disables publication. Give the application account
write permission to the selected directory and ensure BIND can read the files.
The web app needs no root access. The host-specific directory and RNDC tool/key
paths are excluded from application-data archives and preserved on restore.
Retired NAS destination fields in older archives are accepted and discarded;
they never enable remote deployment.

Configure a real authoritative nameserver before deploying zones.
The default ``ns.example.tld`` is an illustrative out-of-zone name.
If either nameserver is inside the LAN zone, create its matching inventory host
so the exported zone contains its A record. Delegate the LAN zone and
each of the four reverse /24 zones to your authoritative server.

Hub-side BIND primary and VPN resolver
--------------------------------------

Configure BIND on the hub to listen on loopback (``lo``) and the VPN
interface (``tun0``). Replace every angle-bracket placeholder below with the
addresses and client/secondary networks for the deployment; no subnet or
host address is built into dnsgrid. The VPN-client ACL is the only ACL granted
recursive or cache access. Authoritative zone queries and zone transfers are
separately restricted. The NAS appliances are secondaries, and LAN clients
should use the NAS resolver on their physical subnet rather than the hub::

    acl vpn_clients { <VPN_CLIENT_CIDR>; };
    acl dns_secondaries { <NAS_SECONDARY_ADDRESS_1>; <NAS_SECONDARY_ADDRESS_2>; };

    options {
        listen-on { 127.0.0.1; <HUB_TUN0_ADDRESS>; };
        recursion yes;
        allow-recursion { vpn_clients; };
        allow-query-cache { vpn_clients; };
        allow-query { localhost; vpn_clients; dns_secondaries; };
    };

    zone "intranet.linuxcondom.net" {
        type primary;
        file "<BIND_ZONE_DIRECTORY>/intranet.linuxcondom.net";
        allow-transfer { dns_secondaries; };
        also-notify { dns_secondaries; };
    };

    zone "vpn" {
        type primary;
        file "<BIND_ZONE_DIRECTORY>/vpn.zone";
        allow-transfer { dns_secondaries; };
        also-notify { dns_secondaries; };
    };

Add a primary zone stanza for each generated reverse zone as well. Configure
each NAS with matching ``type secondary`` stanzas and the hub as its primary.
Restrict transfers to those secondaries (and firewall DNS/RNDC appropriately).
The angle-bracket values are documentation placeholders, not literal BIND
syntax. Review the active configuration and ACLs before enabling recursion.
Set ``lan_domain`` in Settings to ``intranet.linuxcondom.net`` for this
deployment; the application always generates the private VPN origin as ``vpn.``.

In Settings, ``dns_export_directory`` is the existing local BIND zone
directory. Set all three tool paths explicitly and absolutely; for example::

    dns_export_directory = /etc/bind/zones
    named_checkzone = /usr/sbin/named-checkzone
    rndc = /volume1/@appstore/DNSServer/bin/rndc
    rndc_key = /volume1/@appstore/DNSServer/named/rndc.key

The RNDC key path is configuration, not the key material; do not copy its
contents into the database, repository, logs or documentation. Verify that it
is the key authorized by the running BIND ``controls`` block. On publication,
dnsgrid validates every staged zone, atomically replaces zone files while
preserving the existing permission/group model, commits the immutable
generation, then runs exactly one general command::

    <rndc> -k <rndc_key> -s 127.0.0.1 -p 953 reload

This command uses a fixed argument vector, ``shell=False`` and a bounded
timeout. It is never run for a preview, validation failure, incomplete file
installation or incomplete generation commit. If one file fails after others
were replaced, the operation reports partial installation and skips reload;
repair and publish again. No per-zone reload or ``systemctl restart`` occurs.
A successful RNDC exit proves only that the command returned success; dnsgrid
does not query external clients or claim that their resolution was verified.
Check the hub and each secondary separately, for example by checking SOA
serials and the expected records with ``dig``.

The BIND zone directory and command paths are host-local deployment settings
and are excluded from application archives. The application process needs
write access to the zone directory and read access to the RNDC key as required
by the installed BIND package. The validator and RNDC paths are validated as
absolute paths. The repository does not install or alter BIND configuration,
ACLs, package ownership, or firewall rules.

Terminal publication diagnostics
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Publication outcomes use the existing ``dnsgrid.delivery`` logger and go to
the web application's **stderr**. Logs include safe event/status information,
zone names, serial/generation, elapsed time and exit status, but never raw
command output, zone contents or RNDC key material. Validation and reload
commands have bounded timeouts; their stdout/stderr is discarded rather than
forwarded to a browser or log.

To collect detailed diagnostics, set ``DNSGRID_DEBUG=2`` in the environment of
your production WSGI/ASGI service and restart its workers. For a local terminal
session (not a production server), run::

    DNSGRID_DEBUG=2 python manage.py runserver 127.0.0.1:8000

Level 2 does **not** enable Django's web DEBUG mode; it enables terminal
diagnostics only. Level 1 retains its existing development behavior. Level 2
adds publication events such as validation/reload outcome, elapsed time,
generation and sanitized failure status. These diagnostics do not prove
external resolution. No raw process output, credentials, key material or
zone contents are logged. The ``--insecure`` static-file behavior is unchanged.

This repository does not supply a service unit or a fixed deployment log
path. Find logs on the **dnsgrid host**, not in the NAS inbox:

* Foreground execution writes diagnostics to the invoking terminal.
* With a systemd service using journal collection for stdout/stderr, read
  ``journalctl -u <your-dnsgrid-unit> -f``. Check the actual unit's
  ``StandardOutput``/``StandardError`` settings if nothing appears.
* With a container, inspect its configured logging driver and use
  ``docker logs -f <your-dnsgrid-container>`` when that driver supports it.
* With another supervisor or a redirected launcher, use its configured
  stdout/stderr files; ensure stderr is collected, not discarded. There is
  no automatic ``dnsgrid.log`` file.

Restrict access to service logs: they include zone names and generation
metadata. Remove level 2 and restart workers after diagnosis. Web-service
diagnostics cannot verify actual hub or secondary answers; test those directly.

Retired NAS DNS SFTP installer (legacy only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Do not use the DNS SFTP delivery/DSM scheduled-installer workflow below.**
It is retained only as historical migration and recovery documentation; the
application routes and Export page no longer provide DNS zone delivery or
receipt/retry actions. Keep any old DSM task stopped and retire its credentials
and queued deliveries after verifying they are not used by another service.
Use the hub-side publication workflow above. The standalone
``synology/dns_install.py`` remains in the repository for legacy recovery only
and is not part of active DNS publication.

Provision separate paths, for example:

* ``/volume1/dnsgrid-incoming/inbox``: writable by the SFTP account.
  Its parent must not be writable by that account.
* ``/volume1/dnsgrid-results/outbox``: readable, **not writable**, by that
  account. Its parent and every ancestor must prevent the account from
  renaming or replacing the outbox. Do not place it underneath inbox or
  any other SFTP-writable parent.
* ``/volume1/dnsgrid-private/state``: installer-owned mode 0700; stores the
  lock, persistent serial/content identity, transaction journal, private
  validation copies and backups.
* The existing DNS package master directory and validator executable:
  protected administrator or explicitly trusted DSM package-owned paths.
  Keep the script and configuration administrator-owned.

These are examples, not verified DSM paths. Check ownership **and DSM ACLs**,
including inherited ACLs and ancestor permissions, from the SFTP account.
The installer checks POSIX ownership/modes and symlink-free paths; those
checks do not inspect DSM ACLs. Deny the SFTP account write/delete/rename
rights to outbox, state, backups, script, configuration, validator, master
files and their parent directories. The task user must own these protected
paths or they must be root-owned, with no group/world write access.
The inbox itself is the only deliberately untrusted writable directory.
If DSM owns the DNS Server package as ``DNSServer:DNSServer``, optionally set
**both** ``package_owner = DNSServer`` and ``package_root`` to the verified
package installation root (for example ``/volume1/@appstore/DNSServer``).
The account's UID and primary GID are resolved locally, never hardcoded.
Both ``destination_directory`` and ``named_checkzone`` must be descendants
of this root; inbox, outbox and state must be outside it, not its ancestors.
Only within that subtree may directory components and the validator be
root-owned or owned by the configured package account. Symlinks and any
group/world-writable directories or validator are still rejected.
Ancestors outside the subtree retain administrator-only checks.

This explicitly trusts the package account to control the validator and
master directory, including code executed by the privileged installer:
a compromised package account can compromise the installer. Run this mode
as root to set file ownership and restore backups. Keep the SFTP account
separate from the package account and verify DSM ACL isolation; POSIX checks
alone cannot establish that isolation. Do not change DSM package ownership
or permissions to enable this flow.

Copy ``synology/dns_install.py`` by itself to an administrator-owned location.
Python 3 and a working ``named-checkzone`` are prerequisites; ``rndc`` with
a working control-channel key is needed for the optional general reload. Copy and edit
``synology/dns_install.ini.example`` as a protected local INI configuration,
for example ``/etc/dnsgrid-dns-install.ini``. Configure exact authorized
zone names (the LAN zone and all four reverse zones), verified master and
validator paths, inbox, outbox and state. Provision directories in advance;
state and backups must be private. All configured directories are distinct
and must not be nested inside one another (the optional package root is the
explicit exception containing the master directory and validator).

Test locally with the Python executable and paths actually available on DSM::

    python3 /protected/dns_install.py --help
    python3 /protected/dns_install.py --config /protected/dns-install.ini --dry-run

Dry-run validates complete deliveries, including ``named-checkzone``, without
installing files or publishing receipts. It may acquire the lock and create
temporary private copies. Then configure a recurring DSM Task Scheduler task
to execute, with the privileges required for the master files::

    python3 /protected/dns_install.py --config /protected/dns-install.ini

Verify the scheduler's supported recurrence and execution identity on the
installed DSM release. Choose an operationally suitable interval; there is
no guaranteed minimum interval. Expected latency is up to the chosen interval
plus validation/install time and scheduler delays. A second concurrent run
exits busy. Monitor task exit status and protected local diagnostics.

General RNDC reload
~~~~~~~~~~~~~~~~~~~

Running ``named`` does not serve newly installed zone files until it reloads
them. Configure two separate, explicit settings next to the existing
``named_checkzone`` (there is no shared binary-directory setting)::

    named_checkzone = /volume1/@appstore/DNSServer/bin/named-checkzone
    rndc = /volume1/@appstore/DNSServer/bin/rndc
    rndc_key = /volume1/@appstore/DNSServer/named/rndc.key

These paths were verified on one DSM DNS Server package (BIND 9.16.34) whose
active ``named.conf`` controls listen on ``127.0.0.1`` port ``953`` and
authorize key ``rndc-key`` (``hmac-sha256``). ``rndc_key`` must be the key file
authorized by the active ``controls`` block, **not** a zone, transfer or
dynamic-update key such as ``named/etc/key/<zone>-key`` (using one causes
``bad auth`` in the ``named`` log). Verify on your DSM version.

Both settings must be configured together as absolute normalized paths,
outside inbox, outbox, state and destination; one without the other is a
configuration error. The INI contains only the key **path**, never the secret.
``rndc`` is checked like ``named-checkzone`` (regular, single-link, executable,
not group/world writable, symlink-free protected ancestors; package-owned only
inside a configured ``package_root``). ``rndc_key`` must be a regular,
single-link file owned by root, the task user or (inside ``package_root``) the
package account, with no group write and **no world access** (for example mode
``0600`` or ``0640``). The installer checks this metadata but never reads,
logs or copies the key. Check without printing contents::

    stat -c '%U:%G %a %h %F' /volume1/@appstore/DNSServer/named/rndc.key

If the key or executable is missing or unsafe, the installer exits with
configuration status 2 **before installing any file**. It does not generate
keys, edit ``named`` controls/configuration, or restart the package. If an
``/etc/rndc.conf`` exists, ``rndc`` may prefer it over ``-k``; verify the manual
commands below with the same identity as the scheduled task.

After **every** zone in the run's deliveries has been validated and the
installation transaction has committed (journal resolved), the installer runs
exactly one general reload, with ``shell=False``, a fixed argument vector, a
60 second timeout and no zone argument::

    <rndc> -k <rndc_key> -s 127.0.0.1 -p 953 reload

It never reloads after mere SFTP transfer, during ``--dry-run``, after a
rejected or failed delivery that was rolled back without other pending work,
or while recovery is incomplete. Exit status 0 within the timeout is the only
success. Nonzero exit, startup failure or timeout is a reload failure: the
task exits with status **8**, and bounded, control-character-free ``rndc``
output (never the key) is printed to the task's local stderr only.

State ordering for crash safety: files are installed under the existing
journal; once committed, the delivery is recorded in the private
``state/reload.json`` pending-reload record; only then is the reload run and
receipts written; the record is removed only after every receipt is durable.
A crash before the record leaves no receipt, so the next run reprocesses the
delivery as ``already_installed`` and reloads. A crash after the reload
repeats the idempotent general reload. While a pending record exists, every
non-dry run retries the reload **without resending, reinstalling or lowering
serials**; a later ``already_installed`` delivery joins the pending record and
cannot bypass it. An invalid record blocks installation (status 7) for
administrator review; do not delete it to bypass a reload.

Rollback interaction: rollback only happens before the journal is resolved,
which is always before the reload, so ``named`` never loads a partially
installed or rolled-back set from this installer. If an administrator later
restores master files manually, disk restoration alone does **not** change the
zones held in memory: reload ``named`` manually afterwards.

Without ``rndc``/``rndc_key`` (legacy INI), files are installed with the
previous behavior, receipts carry no reload field, their summary states that
reload is not configured, and stderr notes that zones are not confirmed
loaded. Installation without reload does **not** imply the zones are loaded.
After enabling reload for an existing installation, run a manual reload once
or redeliver the current generation (it is processed as ``already_installed``
and reloaded).

Manual diagnostics on the NAS (run as the task user; never print the key)::

    /volume1/@appstore/DNSServer/bin/rndc -k /volume1/@appstore/DNSServer/named/rndc.key -s 127.0.0.1 -p 953 status
    /volume1/@appstore/DNSServer/bin/rndc -k /volume1/@appstore/DNSServer/named/rndc.key -s 127.0.0.1 -p 953 reload
    journalctl -u pkg-DNSServer.service --since "10 minutes ago" --no-pager

Distinguish the outcomes:

* **delivered**: SFTP upload completed; nothing installed yet.
* **installed**: files validated and atomically replaced; ``named`` may still
  serve old data.
* **reload requested**: the installer ran the general ``rndc reload``.
* **reload succeeded**: ``rndc`` exited 0. This does not prove each zone
  loaded or serves the intended records (a zone can still fail to load).
* **serving verified**: only an explicit query, for example
  ``dig @127.0.0.1 <zone> SOA +short`` showing the new serial, verifies it.
  dnsgrid does not perform this check.

Only the operator's manual ``rndc ... status`` on one DSM system has been
verified live; the automated reload is tested with a mocked ``rndc``.

Delivery, receipts and retries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Local publication preserves immutable ``generations/dnsgrid-<serial>`` files
and their checksum manifest. The DNS timestamp serial is independent of
the inventory revision. A delivery adds a unique attempt suffix:
``dnsgrid-<serial>-<32 lowercase hex characters>``.

SFTP creates ``inbox/<attempt>.partial``, uploads zone files, uploads
``manifest.json`` **last**, then renames the directory to ``inbox/<attempt>``.
Never edit a delivered directory. Partial directories are ignored. Failed
or interrupted transfers can leave partial directories; an administrator can
remove abandoned partial directories after checking that no upload is active.
The client never overwrites a delivered generation during a retry.

The installer acquires a lock and copies bounded regular files through
anchored descriptors into private storage. It rejects symlinks, traversal,
unexpected files, unauthorized zone sets, invalid schemas, sizes, checksums
and SOA serials. It runs ``named-checkzone`` on every zone before installation.
One failed validation prevents all files in that delivery from being installed.
It rejects older serials under RFC 1982 and equal serials with different
content; half-range comparisons are ambiguous and rejected.

Backups and a persistent recovery journal precede per-file atomic replacement.
There is **no whole-zone-set atomicity**: readers can observe a mixed set
during installation or rollback. Failure restores previous files; an incomplete
rollback blocks further installation until recovery succeeds. Unrelated
master files are not deleted. Inspect and retain protected backups according
to local policy; there is no automatic NAS backup/inbox/outbox cleanup.
Budget space for deliveries, private copies and backups.

Only ``allowed_zones`` are read or replaced in the master directory; other
zones and DSM metadata directories such as ``@eaDir`` are left untouched.
Existing allowed zone files must be regular, single-link, non-symlink files
with administrator or configured package ownership. Package-owned legacy
files may have mode ``0666`` for baseline validation and backup. Every newly
installed zone is normalized to ``0644`` and, when configured, to the package
account's UID/primary GID before atomic replacement. Rollback restores each
original UID, GID and mode exactly, including legacy writable modes.
Journals now use explicit schema version 2 with ownership metadata. A pending
legacy unversioned journal blocks this installer: complete recovery using the
previous installer before upgrading; do not delete the journal to bypass it.

The installer atomically writes ``outbox/<attempt>.json`` with delivery ID,
serial, status ``installed``, ``already_installed`` or ``failed``, UTC timestamp
and a limited non-secret summary. With reload configured, successful receipts
are written after the reload attempt and add ``reload``: ``succeeded``,
``failed`` (retried by the NAS; the receipt is rewritten after a later
success) or ``superseded`` (a newer installation replaced these files before
a successful reload). Receipts without ``reload`` (legacy or not configured)
remain valid and mean no reload was reported. dnsgrid shows these as
``installed``/``already_installed``, ``reloaded``, ``reload_failed`` and
``superseded``; ``reload_failed`` keeps the generation pinned so **Check NAS
result** can be repeated. Update dnsgrid before enabling reload on the NAS:
older dnsgrid versions reject the extra field as an invalid result.
dnsgrid displays its own bounded messages, not arbitrary remote diagnostics. Use **Check NAS result** to retrieve the
current attempt's receipt. This is an explicit bounded network request, not
continuous polling and not a wait for the next scheduler run.
Until a valid matching receipt is read, installation remains unconfirmed.

SFTP timeout/interruption can happen after delivery rename, so it is reported
as **delivery unconfirmed**. Check the receipt before retrying. An explicit retry
uses the same immutable generation and serial with a fresh attempt ID; an old
attempt's receipt cannot confirm the new one. The installer treats equal-serial,
equal-content retries idempotently. Pending local generations stay pinned until
installation is confirmed; bounded local retention may block new publication
if all retained slots are pending. Resolve receipts before publishing again.
All deployment actions require operator authorization, CSRF and current
inventory revisions.

Migrating an existing deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Back up the database, current hub zones and BIND configuration first. Apply the
new migrations; historical migrations are not rewritten. Configure the local
BIND zone directory and all three explicit tool/key paths in Settings. Verify
directory permissions, BIND ACLs, zone stanzas, secondary transfers and the
serial baseline before publishing.

Stop and retire the old DSM DNS task, SFTP inbox/outbox, receipt polling,
authorized_keys entries, pull wrappers and credentials after verifying that
they are not shared by another service. Old SFTP destination fields may remain
in an upgraded database for compatibility, but are not editable or used by the
active DNS workflow. dnsgrid does **not** revoke credentials or alter NAS,
account, service, firewall or BIND configuration automatically.

Prefer supplying ``DNSGRID_GANDI_TOKEN`` through your deployment's secret
manager; it overrides the saved token. A token entered in Settings is
never rendered back to the browser. Blank preserves it; "Remove saved
Gandi token" clears it. Saved tokens and pending settings confirmations
are stored in the SQLite database/session store, not encrypted at rest.
Restrict database/backups to the service account and use encrypted storage
where required. Tokens must have only the permissions needed for the
managed Gandi domains. No credentials appear in downloaded artifacts.

Exports and deployment
----------------------

The Export previews page displays every artifact and offers downloads.
Downloads never write to system files or deploy BIND/DHCP configuration.
Download links are tied to the preview's inventory revision; regenerate
the preview if inventory changes instead of mixing different revisions.

``forward.zone``
    Preview/download artifact for the configured LAN BIND zone with SOA, NS,
    and A records for every inventory host. Its installed filename is the zone
    name (for example ``intranet.linuxcondom.net``).
``vpn.zone``
    Private ``vpn.`` BIND zone with A records for VPN members only. It is
    independent of the public VPN/Gandi domain and installs as ``vpn.zone``.
``reverse-<g>.zone``
    One BIND /24 reverse zone per site, with LAN FQDN PTR records.
``dsm-reservations-site-<id>.json``
    For each site with a configured DSM interface, the reservation-only
    payload: ``ifname`` and ``reservationData`` containing ``mac``, ``ip``,
    and ``hostname``. MACs are lowercase colon-separated, IPs are the
    site's LAN addresses, and hostnames are dnsgrid's short host names.
    Only MAC-bearing hosts in that site are included, in grid address
    order. Invalid nonempty MACs abort export rather than silently omitting
    reservations. The JSON export alone does not apply changes; it is input
    to the local NAS-side utility described below.
``gandi.json``
    Desired LiveDNS A record sets for hosts with both VPN membership
    and public export enabled. Names are relative to the configured
    Gandi zone; VPN domains must be inside that zone.

The obsolete ``dhcpd.conf``, ``dhcpd-dsm.conf``, and
``dsm-request-site-ID.form`` exports (formerly
``dsm-request-site-<id>.form``) have been removed, along with the authenticated
HTTP form-injection workflow. Use the standalone NAS reservation JSON utility
below instead.

DNS zones begin with explicit ``$ORIGIN`` and ``$TTL`` directives and a
multiline SOA. A and PTR records have explicit FQDN owners and TTLs, sorted
alphabetically by hostname; PTR targets are full LAN FQDNs. Each zone ends
with its zone-apex NS record, configured separately from the SOA nameserver.

After reviewing the preview, use the explicit CSRF-protected ``dns-publish``
POST carrying the preview's ``revision``; stale revisions are rejected.
Previews, GET requests, downloads, saving hosts/Settings, and archive
download/restore never install zones or reload BIND. Installed filenames are
the configured LAN zone name, ``vpn.zone``, and
``<g>.<second>.<first>.in-addr.arpa`` for each reverse zone (the latter two
octets come from ``lan_prefix``). Download names are ``forward.zone``,
``vpn.zone``, and ``reverse-<g>.zone``.

All generated zones are staged in the configured BIND directory and validated
with the explicit ``named_checkzone`` executable before any replacement. Each
target is atomically replaced with ``os.replace``. Existing regular files
retain their read/write permission bits and group ownership; new zones use
mode 0644. The app owns each new inode. Symlink destinations are replaced,
not followed. If a later replacement fails, some files may be new on disk,
but the generation is not committed and RNDC is not invoked. Review and repair
before retrying.

Only after every zone is installed and the immutable generation manifest is
committed does dnsgrid invoke one general RNDC reload. This is not a
whole-zone-set atomic transaction and does not claim external resolution.
Inspect the hub and secondaries directly after publication.

Immutable local generations
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Successful local publication also writes copies under
``generations/dnsgrid-<serial>/``, then commits ``manifest.json`` atomically
**last**, after every mutable zone file and immutable generation file succeeds.
The manifest contains version 1, generation, serial, UTC publication time and
zone name/filename/byte-size/SHA-256 entries. The generation identifier is
exactly ``dnsgrid-`` plus the canonical decimal uint32 serial, without leading
zeroes (including ``dnsgrid-0``). Limits are 256 zones,
4 MiB per zone and 128 KiB per manifest. The root ``manifest.json`` is a latest copy for inspection only.
``manifest.json`` is a reserved filename and cannot be a managed zone name.
Same-serial files must be byte-identical; collisions require a seed that
advances under RFC 1982.
Republishing unchanged content retains the original generation/time.
Use a real, symlink-free export path on a local filesystem that supports hard
links, atomic rename and fsync. Restrict writes to one dnsgrid installation.

Ten identified, committed application-owned generations are retained.
Pruning never traverses symlinks or removes unidentified directories/files,
the current generation, or existing ``.pin``-marked generations.
Inventory's singleton write lock covers publication and pruning. Existing pins
remain protected and can fill retention and block new generation commits.
Old DNS SFTP deliveries may have left pinned generations; those pins are
legacy metadata, not part of the active publisher. An administrator must
review unresolved pins before manual removal. Incomplete or
unidentified crash remnants are not pruned automatically; an administrator
must inspect them before removal. No other hub files are deleted.

These are dedicated application-owned artifacts. Assign dnsgrid exclusive
ownership of its LAN forward zone and site reverse zones; do not replace
existing user-managed zones with downloads. For a mixed deployment merge
explicitly reviewed records or use separate delegated zones. Include or
merge hosts artifacts into configurations you own; the app does
not manage unrelated stanzas, leases, options, routers, or dynamic pools.
DSM uses ``SYNO.Network.DHCPServer.Reservation.set`` for reservations.
User testing observed local writes updating
``/etc/dhcpd/dhcpd-<ifname>-static.conf``, ``/etc/dhcpd/dhcpd.conf``, and
``/etc/dhcpd/dhcpd.info``.
Send reservation data through DSM rather than editing these system files
or modifying package binaries, service units, or scripts. These exports
do not contain DHCP pools, gateway, DNS options, or lease settings.

Review the preview and back up the destination interface's reservations
before applying. Each site's artifact contains its complete reservation
set, including an empty list when no hosts have MACs. Treat ``set`` as
replacing the entire interface list: merge any unrelated reservations
explicitly before sending it. Target the correct site's DSM server and
interface; do not apply separate site lists to the same server/interface.
Check both the outer ``success`` and inner result's ``success``, and ensure
``data.has_fail`` is false. Verify the resulting reservations in DSM's UI.
Downloads never modify DSM files or package services, and active leases
do not change automatically.

Local DSM reservation application
---------------------------------

Run this operator workflow **on the target NAS with sudo**, not inside the
web app. The utility uses only Python 3's standard library: no Django,
virtualenv, inventory database, DSM web login, or remote authentication is needed.
Install Python 3 on the NAS if necessary. Manually copy only the repository's
``synology/dsm_apply.py`` and the downloaded
``dsm-reservations-site-<id>.json`` onto the NAS, for example into
``/volume1/dnsgrid``; the rest of the repository is not required.
Review the JSON's ``ifname`` against the site's LAN
subnet and the target NAS; it comes from site Settings, never a hard-coded
interface.

Read-only preview (also accepts an explicit ``--dry-run``)::

    sudo python3 /volume1/dnsgrid/dsm_apply.py \
      /volume1/dnsgrid/dsm-reservations-site-1.json \
      --backup-dir /volume1/dnsgrid/backups

Apply after reviewing the diff and answering ``y`` to the confirmation::

    sudo python3 /volume1/dnsgrid/dsm_apply.py \
      /volume1/dnsgrid/dsm-reservations-site-1.json \
      --backup-dir /volume1/dnsgrid/backups --apply

``--yes`` instead of ``--apply`` explicitly authorizes writing without
a prompt. Without either flag, no write occurs. **This replaces the full
reservation list for the interface**, including deleting all reservations
when the array is empty. Merge unrelated reservations into the JSON
explicitly if they must be retained. It does not manage pools, DHCP
options, leases, or the rest of the server configuration.

The utility:

1. Validates the export and reads locally using
   ``SYNO.Network.DHCPServer.Reservation.get`` **version 3** via
   ``/usr/syno/bin/synowebapi --exec``.
2. Converts ``data.reservationList.ipv4[].clid`` to ``mac``, preserving
   hostname/IP pairs. This feature is **IPv4-only**: it fails before
   writing if ``ipv6`` is nonempty or malformed, or an IPv4 entry cannot
   be safely converted. No unsupported entries are silently skipped.
3. Creates a unique, timestamped private backup directory before any
   write (also during a dry run). ``response.json`` contains the full
   parsed DSM response, including any returned metadata;
   ``reservations.json`` contains the converted, restorable
   ``ifname`` / ``reservationData`` export. Directories are mode 0700
   and files 0600. Backup failure prevents writing.
4. Shows counts and a diff of additions, deletions, and changed mappings,
   then requires ``--yes`` or ``--apply`` and confirmation. A second read
   rejects changes since the preview, including newly added IPv6 entries.
5. Calls ``SYNO.Network.DHCPServer.Reservation.set`` **version 2** with
   separate JSON-encoded ``ifname`` and ``reservationData`` arguments.
   **The latter is the raw array of objects with mac, ip, and hostname,
   not the wrapper object containing ifname and reservationData.**
6. Re-reads with ``get`` version 3 and verifies all MAC/IP/hostname
   mappings, independent of list ordering and MAC letter case. API errors
   or verification mismatches exit nonzero.

To restore, review the saved ``reservations.json`` and pass its absolute
path to the same utility, previewing first and then using ``--apply``.
The restoration is itself a full-list replacement with a new backup.
If writing or verification fails, inspect the reported backup and DSM's
UI before deciding whether to restore; there is no automatic rollback.
Avoid concurrent DSM reservation edits: the pre-write recheck detects
stale previews but DSM provides no atomic compare-and-set here.
No direct writes to ``/etc/dhcpd`` or package modifications are made.
Copying/downloading an export alone never applies it.

Output ordering is deterministic. BIND serials use the persisted DNS content
serial, separate from inventory revision: unchanged DNS content yields identical
exports, and DNS-changing mutations allocate ``max(now, last + 1)``. Back up
the database to preserve serial continuity. Before deployment, validate
the downloaded files with your existing tools, for example::

    named-checkzone intranet.example.tld forward.zone
    named-checkzone 1.168.192.in-addr.arpa reverse-1.zone

For planned moves, reduce TTL sufficiently ahead of time, wait out the
previous TTL, publish forward/reverse records together, refresh DHCP,
and coordinate client renewals and routing. Negative DNS caches can also
delay new names. VPN member DNS records are published in the private
``vpn.`` primary zone and transferred to the NAS secondaries.

VPN alignment report
--------------------

dnsgrid is meant to run on the VPN center. The "VPN report" page compares
dnsgrid's VPN members with that machine's ``/etc/hosts`` and
``/etc/openvpn/ccd/`` and lists discrepancies. **It is strictly
read-only**: it only opens files for reading and lists the directory; it
never writes, corrects, or deletes ``/etc/hosts``, CCD files, or service
files and never reloads OpenVPN or resolvers. dnsgrid no longer generates or
exports a hosts file; keep ``/etc/hosts`` to its existing narrow local use and
fix report discrepancies manually.

For every host with VPN membership (every status) it checks that:

* ``/etc/hosts`` maps ``name.vpn`` to the computed VPN address exactly
  once (missing, duplicate, invalid, or different addresses are reported);
* ``/etc/openvpn/ccd/<name>`` exists, is readable, and contains exactly one
  active ``ifconfig-push <ip> <netmask>`` directive whose IP is the computed
  VPN address. Missing, multiple, or malformed directives (not two IPv4
  arguments) are reported. The netmask/peer is shown but not compared,
  because dnsgrid does not model the OpenVPN topology.

Orphans are also listed: ``*.vpn`` names in ``/etc/hosts`` that are not
dnsgrid VPN members, and CCD entries that do not match a VPN member's name.
Only ``*.vpn`` names in ``/etc/hosts`` are in scope; other entries such as
``localhost`` or LAN names are ignored. OpenVPN's ``DEFAULT`` CCD file is
ignored. Missing, unreadable, oversized (over 1 MiB), or wrong-type sources
are reported as not inspected rather than treated as aligned. The report
checks files only, not connected clients or DNS resolution.

Paths are deployment settings, never user input: override them with the
``DNSGRID_VPN_HOSTS_FILE`` and ``DNSGRID_VPN_CCD_DIR`` environment variables
(defaults ``/etc/hosts`` and ``/etc/openvpn/ccd``). Grant the dnsgrid
service account read access to them only; do not run dnsgrid as root.

Gandi ownership and synchronization
----------------------------------

"Fetch Gandi preview / diff" reads LiveDNS without changing it. Confirm
performs another read and rejects stale inventory, changed remote records,
or ownership conflicts before applying record-level operations.

The local ``GandiRecord`` ledger tracks only records created successfully
by this installation. Existing unmanaged A records, even identical ones,
and conflicting CNAMEs are never adopted or overwritten automatically.
Updates/deletions require the remote value and TTL to match the last
owned version. Unrelated records remain untouched. Changing names,
domains, sites, or export flags reconciles old owned records as well as
new desired records. Repeating a successful sync performs no writes.

Successful operations checkpoint their ledger independently. If a later
API call fails, generate another preview to reconcile partial success.
If a request timed out after a remote mutation, or the process stopped
before its ledger commit, the next preview conservatively reports a
conflict rather than assuming ownership. Resolve that situation with a
DNS administrator. Never discard the ledger to "force" a sync.
Back up ``db.sqlite3`` including both inventory and ownership ledger.

LiveDNS has no conditional/ETag writes: fresh per-record reads reduce but
cannot eliminate a concurrent external-edit race. Do not edit dnsgrid-owned
records concurrently from other tools. The app never replaces a whole
Gandi zone. Real sync requires configured credentials and connectivity;
tests use a fake provider and never contact Gandi.

Application-data portability
----------------------------

Export previews offers ``dnsgrid-archive-v1.json``. Settings includes an
explicit application-archive file upload section and preview button; a
standalone upload/restore form is also linked from Export previews.
Only authenticated staff can use them. Downloads are read-only,
noncacheable, and bound to the preview revision. Upload previews make no
inventory writes; the existing nonce-based POST confirmation is required
to apply a replacement, with separate acknowledgments for target conflicts
and trusted same-scope Gandi ownership.

The deterministic UTF-8 JSON schema has exactly these top-level keys:

* ``format``: exact string ``"dnsgrid.application-data"``.
* ``schema_version``: integer ``1``.
* ``configuration``: ``id`` (always 1), ``lan_domain``, ``vpn_domain``,
  ``lan_prefix``, ``vpn_prefix``, ``gandi_zone``, ``ttl``, ``soa_ns``,
  ``soa_mailbox``, ``soa_refresh``, ``soa_retry``, ``soa_expire``,
  ``soa_minimum``, ``zone_ns``, and ``revision``. Older v1 archives without
  these new SOA timing and zone NS fields remain accepted. Legacy migration
  and archive compatibility retain the old SOA timing values and existing
  nameserver rather than changing them to new DSM defaults.
  ``dns_export_directory`` is host-specific and excluded.
* ``sites``: exactly four objects with ``id`` (1–4), ``name``, ``g``, and
  ``dsm_ifname``. Older v1 archives without ``dsm_ifname`` are accepted
  with an empty mapping; new exports include it.
* ``hosts``: objects with ``id``, ``name``, ``site_id``, ``row``, ``column``,
  ``category``, ``status``, ``vpn``, ``public_export``, ``mac``, and ``notes``.
  Every status is included, with IDs and positions preserved.
* ``gandi_records``: ownership objects with ``id``, ``zone``, ``name``,
  ``record_type`` (``A``), ``values``, and ``ttl``.

Lists are ordered by IDs; ownership values and JSON keys are sorted.
Unknown fields, missing required fields, duplicate JSON keys, wrong types
(including booleans for integers), invalid references, duplicates, and violated model invariants
are rejected. Uploads and pending archive data are bounded to 8 MiB, 127
hosts, 1,024 ownership records, and 1–16 IPv4 values per owned record.
The byte bound accommodates the complete grid with maximum-length Unicode
notes and categories, including supplementary characters serialized as
JSON escape pairs.
Host and ownership IDs must be integers from 1 through ``2**53 - 1``
(9,007,199,254,740,991). This JSON-safe range leaves ample signed-64-bit
headroom for SQLite's automatic allocations; sequence-exhausting IDs are
rejected rather than reset or reassigned.
If an imported ID reaches this portable bound, subsequent new hosts and
ownership records receive the lowest unused portable ID under the existing
configuration lock. This remains true after deleting the high-ID record:
existing IDs and SQLite sequences are never reset, and allocation adds no
revision increment of its own.
Incoming settings and hosts are validated together, independent of the
outgoing inventory. Each ownership record must belong to the incoming
configured zone and a direct host label beneath its VPN domain.
Historical owned IPv4 values need not match current desired addresses:
they are retained so future sync can safely delete obsolete records.

Confirmation replaces settings, fixed-site mappings, hosts, and the ledger
atomically with foreign-key-safe ordering. It preserves destination users
and the saved token, as well as the destination's ``dns_export_directory``.
The resulting revision is
``max(destination revision, archive revision) + 1``; serial overflow,
stale inventory, or changed target ownership rejects the replacement.
Neither preview nor restore calls Gandi. Subsequent provider previews
still refuse unmanaged collisions and remotely modified owned records.
There is no automatic DNS/DHCP/Gandi deployment.

Migration checklist:

1. Stop source inventory changes and Gandi synchronization. Never operate
   source and destination as simultaneous writers for the same scope.
2. Make an offline, consistent database backup of both installations
   before replacement (stop processes, including workers; preserve SQLite
   journal/WAL state correctly or use SQLite's backup facilities).
3. Download the source application archive. Treat host notes and ownership
   history as sensitive operational data; transfer it securely.
4. Install/migrate the destination and run ``python manage.py createsuperuser``.
   Provision deployment secrets and Gandi credentials separately.
5. Upload and inspect the settings/site/host/ledger diff and serial. Accept
   replacement of target conflicts only deliberately. Import ownership
   only from a trusted archive for the **SAME Gandi domain and control
   scope**: it grants authority to update/delete matching remote records.
   Migrate only within that same managed domain/control scope, retaining
   the source and its offline backup. For a new scope, establish a separate,
   independently reviewed inventory; do not discard ownership history.
6. Confirm, verify inventory and generated artifacts, then fetch a fresh
   provider preview. Resolve conflicts with a DNS administrator rather
   than bypassing ownership safety. Leave the old writer stopped.

This is **not a byte-for-byte database backup**. Authentication users,
passwords, sessions, pending confirmations, tokens, environment/deployment secrets, and unrelated
database state are excluded. Keep an offline database backup for recovery;
restore archives only through the reviewed application workflow.

Development checks
------------------

The project uses Django's built-in test runner::

    python manage.py test inventory
    python manage.py check
    python manage.py makemigrations --check --dry-run

Tests cover grid boundaries, shifts, rollback, no-compaction deletions,
site moves, validation, deterministic artifacts, export membership,
MAC normalization, Gandi conflicts/idempotency/failure recovery, operator
authorization, CSRF, confirmation workflows, and token redaction.
NAS tests cover SFTP batch delivery, asynchronous receipt validation,
immutable retries, hostile inbox acquisition, installer locking, validation,
rollback/recovery, dry-run and a copied standalone CLI. They do not replace
testing SFTP authentication, DSM ACLs/scheduler, real BIND validation and zone
loading on the deployed NAS.
