Debian 13 production deployment (dnsgrid 1.1.0)
=============================================

This deployment replaces ``runserver --insecure`` with Gunicorn and Nginx.
It preserves ``http://172.28.0.1:8000`` exclusively on the VPN, uses the
existing ``dnsgrid`` account and ``/var/www/dnsgrid`` checkout, and starts
at boot. It does not configure BIND, OpenVPN, DHCP or firewall rules.
The host must already provide ``tun0`` through ``openvpn.service``.

HTTP relies entirely on VPN transport protection. Do not expose port 8000
on another interface or forward it from the Internet. ``DNSGRID_DEBUG=2``
enables terminal diagnostics, not Django's web DEBUG mode.

Prepare without stopping the current application
-----------------------------------------------

Run on the actual Debian hub as an administrator. The repository automation
does not install services on that machine. Adapt paths if the existing
checkout or virtual environment differs; do not create an empty database
in a second checkout.

Install the prerequisites::

    sudo apt-get update
    sudo apt-get install nginx python3-venv
    cd /var/www/dnsgrid

Use the existing virtual environment, or create one if absent::

    sudo -u dnsgrid python3 -m venv .venv
    sudo -u dnsgrid .venv/bin/python -m pip install -r requirements-production.txt

The second command is also the dependency update procedure on subsequent
deployments. Nginx may start its packaged default site during installation;
inspect existing sites and listeners before installing the configuration.
Do not overwrite unrelated sites or global Nginx settings.

Create the private environment file::

    sudo install -d -o root -g root -m 700 /etc/dnsgrid
    sudo install -o root -g root -m 600 deploy/dnsgrid.env.example /etc/dnsgrid/dnsgrid.env
    sudo -u dnsgrid .venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(64))'
    sudoedit /etc/dnsgrid/dnsgrid.env

Replace the placeholder secret with the generated value. Keep it stable
across reboots and workers; do not paste it into chat or commit it.
If there is already a persistent ``DNSGRID_SECRET_KEY``, keep that value.
Otherwise the initial change invalidates existing login sessions.
Copy any other currently used settings, such as a Gandi environment
override, into this root-readable file. It uses ``NAME=value``, not
``export``. Never overwrite this file during later upgrades.

The retired ``DNSGRID_DNS_SFTP_KNOWN_HOSTS`` and
``DNSGRID_DNS_SFTP_IDENTITY_FILE`` settings are not needed. Keep unrelated
SSH files intact; their removal is not part of this deployment.

Nginx runs as ``www-data``. It must traverse ``/var/www/dnsgrid`` and read
only the collected static assets. Do not grant it database, RNDC key,
Gandi credential or OpenVPN CCD access. Preserve the existing ``dnsgrid``
user's permissions on the database and its directory (SQLite needs journal
and WAL access), BIND zone output, RNDC key and CCD report source.
The application service uses primary group ``www-data`` only for the private
upstream socket, explicitly retains group ``dnsgrid`` for existing files
such as the RNDC key, and retains the account's supplementary groups.

Install the units and site::

    sudo install -o root -g root -m 644 deploy/dnsgrid.service /etc/systemd/system/dnsgrid.service
    sudo install -o root -g root -m 644 deploy/nginx-dnsgrid.conf /etc/nginx/sites-available/dnsgrid
    sudo ln -s /etc/nginx/sites-available/dnsgrid /etc/nginx/sites-enabled/dnsgrid
    sudo install -d -o root -g root -m 755 /etc/systemd/system/nginx.service.d
    sudo install -o root -g root -m 644 deploy/nginx-openvpn.conf /etc/systemd/system/nginx.service.d/dnsgrid-vpn.conf
    sudo systemctl daemon-reload
    sudo nginx -t

If the symlink already exists, inspect it instead of recreating it.
Do not add this site to an Nginx configuration that trusts arbitrary
``real_ip_header`` / ``set_real_ip_from`` sources: the peer IP must remain
the actual VPN client address. No proxy or NAT may hide that address.
The drop-in waits up to 90 seconds for ``172.28.0.1`` on ``tun0`` and
logs a failed start if it never appears, retrying after 10 seconds.
Adapt the address in both Nginx and
the drop-in, and allowed hosts, if the deployment address changes.
The drop-in affects startup of the whole Nginx service; use it on the hub
with that dependency understood, not blindly on a shared web server.

Cutover
-------

Schedule a short maintenance window. Stop the manual ``runserver`` with
Ctrl-C in its terminal before switching the listener. Back up the database
and deployment configuration while the application is stopped. Preserve
the existing database, inventory and publication history; do not reset them.

Then run migrations and collect static files using the same environment
as the service. Start a temporary shell as root, load the trusted
root-owned environment file, and run Django as ``dnsgrid``::

    sudo -i
    set -a
    . /etc/dnsgrid/dnsgrid.env
    set +a
    cd /var/www/dnsgrid
    runuser -u dnsgrid --preserve-environment -- .venv/bin/python manage.py migrate
    runuser -u dnsgrid --preserve-environment -- .venv/bin/python manage.py collectstatic --noinput
    runuser -u dnsgrid --preserve-environment -- .venv/bin/python manage.py check --deploy
    exit

The environment example uses syntax compatible with both this shell
procedure and systemd. Quote additional values consistently for both.
``check --deploy`` will warn about HTTP cookies, HTTPS redirects and HSTS:
these are intentional for this VPN-only HTTP deployment. Investigate other
warnings, and never enable web DEBUG to clear or bypass checks.

Set collected assets readable by Nginx without opening other application
data, and ensure the checkout's ancestors allow traversal::

    sudo chgrp -R www-data /var/www/dnsgrid/staticfiles
    sudo find /var/www/dnsgrid/staticfiles -type d -exec chmod 750 {} +
    sudo find /var/www/dnsgrid/staticfiles -type f -exec chmod 640 {} +

The account running ``collectstatic`` must retain write access for upgrades.
Reapply these static-file permissions after future collection.
If necessary, grant ``www-data`` traverse-only access to the checkout
directory using a targeted ACL; do not recursively chmod the checkout.

Enable the application, the existing VPN service, and Nginx::

    sudo systemctl enable openvpn.service
    sudo systemctl enable --now dnsgrid.service
    sudo systemctl enable nginx.service
    sudo systemctl restart nginx.service

Do not enable ``DNSGRID_HTTPS=1`` for this HTTP deployment: that would redirect
clients to a nonexistent HTTPS listener and require secure cookies.
Do not run ``runserver`` alongside Nginx on the same address and port.

Verify and operate
------------------

From a VPN client, verify login, CSS/JavaScript, a normal DHCP pull, and PAT
access from an authorized inventory host. Check that the applied DHCP
version is still reported and that unauthorized hosts cannot retrieve
the PAT. Do not print the PAT response body during diagnostics::

    curl -I http://172.28.0.1:8000/accounts/login/
    curl -I http://172.28.0.1:8000/static/inventory/style.css
    curl -I http://172.28.0.1:8000/static/inventory/grid.js
    sudo systemctl status dnsgrid nginx --no-pager
    sudo journalctl -u dnsgrid -u nginx -b --no-pager
    sudo ss -lntp
    sudo ss -lxnp

The Nginx file syntax can be checked with ``sudo nginx -t`` before any
restart. Gunicorn startup failures (including an unset or placeholder
secret, or ``DNSGRID_DEBUG=1``) are explicit in the service journal.

Only Nginx should listen on ``172.28.0.1:8000``; Gunicorn has no TCP
listener. The socket directory is ``dnsgrid:www-data`` mode 750, with a
mode-770 socket accessible only to that user/group and root. Keep membership
of ``www-data`` restricted: anyone who can connect to that socket can
impersonate a VPN client. Nginx overwrites ``X-Real-IP`` and strips other
forwarding headers; the production WSGI entry point trusts this header
only on Unix-socket connections. The development entry point continues
to ignore forwarded headers. Do not use the production entry point with a
public or TCP upstream, and do not cache the PAT endpoint.

Reboot the hub in a planned window and repeat the checks. The boot
dependency and actual VPN configuration can only be verified on that host.
If the tunnel is late or unavailable, inspect the Nginx journal, restore
OpenVPN, then ``sudo systemctl restart nginx``.

For code upgrades: back up, update the checkout, install production
requirements, migrate and collect static assets with the service
environment, restore their permissions, then restart ``dnsgrid``.
Migrations and destructive operations must not run concurrently with
application writes; use a maintenance window.
Restart the service after editing its environment. Configuration and
secrets live outside Git and survive code updates.

Rollback of the server switch (not database migrations)
------------------------------------------------------

Stop ``dnsgrid`` and temporarily remove only the dnsgrid Nginx site symlink,
then restart Nginx so port 8000 is released. Disable ``dnsgrid`` to prevent
an unexpected application restart. Remove the Nginx drop-in if the VPN
dependency is no longer desired; reload systemd afterwards. Preserve
all data and secrets. If required during investigation, temporarily run
the previous VPN-bound ``runserver --insecure`` as ``dnsgrid`` with its
original environment. This is diagnostic rollback, not production hosting.
