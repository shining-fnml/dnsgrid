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

This is the workflow the application supports for my conventions, not a
description of a particular live deployment. All hosts and domains below
are fictitious examples.

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
3. Review Export previews and download the required artifacts for manual
   validation and deployment. ``vpn.hosts`` supplies local aliases such
   as ``172.28.1.50 demo-node.vpn`` for every VPN member. Public DNS is
   separate: only VPN members with public export enabled produce Gandi
   A records, using the configured VPN domain (for example
   ``demo-node.vpn.example.tld``) and the computed VPN address. Public DNS
   publication does not make these private addresses Internet-routable.
   Neither that FQDN nor the bare name belongs in ``vpn.hosts``: local
   aliases must not mask whether the public FQDN resolves through DNS.
   Gandi changes require a separate preview and explicit confirmation.
4. For Synology reservations, configure the site's DSM interface, download
   its JSON, and manually copy it and ``synology/dsm_apply.py`` to the
   target NAS. Preview there before explicitly applying the complete
   interface reservation list. Only this standalone NAS-side operation
   uses sudo; the web application does not apply DSM changes.
5. On the VPN hub, run the web app as an unprivileged service account with
   read access to ``/etc/hosts`` and ``/etc/openvpn/ccd`` (or the configured
   paths). Use VPN report to compare ``name.vpn`` and CCD ``<name>`` files
   against inventory, including orphans and unreadable sources. Correct
   discrepancies manually; the report neither writes files nor checks
   live clients or DNS. The ``vpn.hosts`` download remains available for
   manual use; review and merge it without replacing unrelated hosts entries.

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
Leave ``DNSGRID_DEBUG`` unset in production.

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
``soa_minimum``, and the separate zone-apex ``zone_ns``, the Gandi zone,
and an optional Gandi token. ``soa_ns`` is the SOA primary nameserver;
``zone_ns`` supplies the zone's NS record.
Each site also has an optional DSM DHCP interface name (for example
``ovs_eth0``). Set it to the interface serving that site's LAN subnet
on its DSM server; leaving it blank disables that site's DSM API exports.
The SOA mailbox is a DNS name such as ``hostmaster.example.tld``, not
an email address. Defaults derive ``192.168.g.x`` and ``172.28.g.x``.
The SOA serial automatically uses the persisted inventory revision.
Settings' ``soa_serial`` field can seed that revision upward: choose a value
exceeding an existing DSM zone serial before replacing its zone. It is not
a separate fixed serial; subsequent inventory/settings changes advance it.

``dns_export_directory`` is an optional absolute path to an existing directory
on the dnsgrid host. Blank disables directory publishing. Give the application
account write permission only to the selected directory; the web app needs no
root access or SSH integration. This host-specific path is excluded from
application-data archives and preserved on restore.

Configure a real authoritative nameserver before deploying zones.
The default ``ns.example.tld`` is an illustrative out-of-zone name.
If either nameserver is inside the LAN zone, create its matching inventory host
so the exported zone contains its A record. Delegate the LAN zone and
each of the four reverse /24 zones to your authoritative server.

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
    One LAN BIND zone with SOA, NS, and A records for every inventory host.
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
``vpn.hosts``
    One ``ip name.vpn`` line per VPN member, including those not publicly
    exported, for example ``172.28.1.50 alpha.vpn``. It contains neither
    the public VPN FQDN (``alpha.vpn.example.tld``) nor the bare host name.
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

After reviewing the preview, use **Write DNS zones to directory** to publish.
This is an explicit CSRF-protected POST to ``dns-publish`` carrying the preview's
``revision``; stale revisions are rejected. The configured
``dns_export_directory`` is displayed on the page. Saving hosts or Settings,
downloads, and archive download/restore never implicitly write zones.
Deposited filenames are the zone names, without a ``.zone`` suffix:
``lan_domain`` for the forward zone and
``<g>.<second>.<first>.in-addr.arpa`` for each reverse zone (the latter two
octets come from ``lan_prefix``). Download names remain ``forward.zone`` and
``reverse-<g>.zone``.

Each zone is written to a temporary file in the destination directory and
atomically replaced with ``os.replace``. Existing matching files are overwritten
without a prompt; no backups are made and no unrelated files are deleted.
The entire set is **not atomic**: per-file errors are reported, and some zones
may already have been replaced when another fails. Review errors and retry
after correcting permissions or other failures. User testing observed DSM
automatically reloading deposited zones; this is not a universal guarantee.
Verify loading on your installation and reload through your normal operator
workflow if necessary.

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

Output ordering is deterministic. BIND serials use the persisted inventory
revision, not the clock: unchanged inventory yields identical exports,
and successful inventory/settings changes increase the serial. Back up
the database to preserve serial continuity. Before deployment, validate
the downloaded files with your existing tools, for example::

    named-checkzone intranet.example.tld forward.zone
    named-checkzone 1.168.192.in-addr.arpa reverse-1.zone

For planned moves, reduce TTL sufficiently ahead of time, wait out the
previous TTL, publish forward/reverse records together, refresh DHCP,
and coordinate client renewals and routing. Negative DNS caches can also
delay new names. VPN hosts-file changes require reloading the relevant
dnsmasq/resolver configuration on the VPN center.

VPN alignment report
--------------------

dnsgrid is meant to run on the VPN center. The "VPN report" page compares
dnsgrid's VPN members with that machine's ``/etc/hosts`` and
``/etc/openvpn/ccd/`` and lists discrepancies. **It is strictly
read-only**: it only opens files for reading and lists the directory; it
never writes, corrects, or deletes ``/etc/hosts``, CCD files, or service
files and never reloads OpenVPN or resolvers. Fix reported items manually.
The ``vpn.hosts`` download on Export previews is unchanged and remains the
way to obtain the expected hosts lines.

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
  these new SOA timing and zone NS fields remain accepted with compatible
  defaults. ``dns_export_directory`` is host-specific and excluded.
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
