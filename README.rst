dnsgrid
=======

A dedicated DNS inventory application: one global 16-row, 8-column grid,
four geographic sites, and deterministic DNS/DHCP exports. Built with
Python 3.12+ and Django, using SQLite without a separate frontend build.

Quick start
-----------

From ``/home/runner/work/dnsgrid/dnsgrid``::

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
* Preview and confirm host changes, deletions, and global settings.
  Diffs show affected addresses and metadata. Inventory revisions
  reject stale forms and stale confirmations; refresh and preview again.
* ``running``, ``decommissioned``, and ``unconfirmed`` are informational.
  Nothing expires automatically and statuses never enter exports.
* Occupied grid cells use dark ink by stable site ID: 1 blue, 2 green,
  3 red, 4 gold, independent of site names or subnet octets. Their surfaces
  stay light even in dark mode; the rest of the application retains its
  theme. VPN names alone are bold, unconfirmed cells are light gray, and
  decommissioned names appear as ``[name]`` only in the grid. Stored names,
  FQDNs, and exports are unchanged. The legend uses configured site names.
* Names are unique DNS labels. MACs accept colon, hyphen, dotted, or
  compact hexadecimal formats and normalize to lowercase colon form.
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
the four site names and distinct third octets, TTL, authoritative NS
and SOA mailbox names, the Gandi zone, and an optional Gandi token.
The SOA mailbox is a DNS name such as ``hostmaster.example.tld``, not
an email address. Defaults derive ``192.168.g.x`` and ``172.28.g.x``.

Configure a real authoritative nameserver before deploying zones.
The default ``ns.example.tld`` is an illustrative out-of-zone name.
If the NS is inside the LAN zone, create its matching inventory host
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
``dhcpd.conf``
    One ISC DHCP configuration with all four subnet declarations and
    reservations for MAC-bearing hosts. Reservations use LAN FQDNs, not
    IP literals. Site-only moves leave reservations unchanged.
``vpn.hosts``
    VPN addresses, VPN FQDNs, and short aliases for all VPN members,
    including those not publicly exported.
``gandi.json``
    Desired LiveDNS A record sets for hosts with both VPN membership
    and public export enabled. Names are relative to the configured
    Gandi zone; VPN domains must be inside that zone.

These are dedicated application-owned artifacts. Assign dnsgrid exclusive
ownership of its LAN forward zone and site reverse zones; do not replace
existing user-managed zones with downloads. For a mixed deployment merge
explicitly reviewed records or use separate delegated zones. Include or
merge DHCP and hosts artifacts into configurations you own; the app does
not manage unrelated stanzas, leases, options, routers, or dynamic pools.

Output ordering is deterministic. BIND serials use the persisted inventory
revision, not the clock: unchanged inventory yields identical exports,
and successful inventory/settings changes increase the serial. Back up
the database to preserve serial continuity. Before deployment, validate
the downloaded files with your existing tools, for example::

    named-checkzone intranet.example.tld forward.zone
    named-checkzone 1.168.192.in-addr.arpa reverse-1.zone
    dhcpd -t -cf dhcpd.conf

For DHCP validation and operation, LAN FQDNs must already resolve on the
DHCP server. ISC dhcpd resolves ``fixed-address`` names when it reads its
configuration: publish DNS first, wait for old caches to expire, then
reload/restart DHCP to resolve moved hosts. No textual reservation edit
is needed for a site move, but running DHCP does not continuously refresh
these names. Active leases do not change automatically.

For planned moves, reduce TTL sufficiently ahead of time, wait out the
previous TTL, publish forward/reverse records together, refresh DHCP,
and coordinate client renewals and routing. Negative DNS caches can also
delay new names. VPN hosts-file changes require reloading the relevant
dnsmasq/resolver configuration on the VPN center.

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
