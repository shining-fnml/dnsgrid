import re
from pathlib import Path

from django.core.exceptions import ValidationError
from django.core.validators import MaxLengthValidator, MaxValueValidator, MinValueValidator, RegexValidator
from django.db import connections, models, router, transaction
from django.db.models import F, Q

from .dns_serial import initial_serial


MAX_SERIAL = 2**32 - 1
MAX_PORTABLE_ID = 2**53 - 1
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _save_portable_identity(instance, save, *args, **kwargs):
    using = kwargs.get("using") or (args[2] if len(args) > 2 else None)
    using = using or router.db_for_write(type(instance), instance=instance)
    connection = connections[using]
    if instance.pk is not None or connection.vendor != "sqlite":
        return save(*args, **kwargs)
    # Keep the sequence read and normal insertion in the same SQLite snapshot:
    # a competing boundary insertion fails safely instead of overflowing it.
    with transaction.atomic(using=using):
        with connection.cursor() as cursor:
            cursor.execute("SELECT seq FROM sqlite_sequence WHERE name = %s", [instance._meta.db_table])
            sequence = cursor.fetchone()
        if sequence is None or sequence[0] < MAX_PORTABLE_ID:
            return save(*args, **kwargs)
        force_update = kwargs.get("force_update", args[1] if len(args) > 1 else False)
        update_fields = kwargs.get("update_fields", args[3] if len(args) > 3 else None)
        if force_update or update_fields is not None:
            return save(*args, **kwargs)
        # An imported high ID permanently raises AUTOINCREMENT, even if deleted.
        # Serialize gap allocation with the existing singleton, without bumping
        # its revision or modifying either existing IDs or sqlite_sequence.
        if not Configuration.objects.using(using).filter(pk=1).update(revision=F("revision")):
            raise ValidationError("A configuration is required to allocate a portable identity.")
        candidate = 1
        for pk in type(instance).objects.using(using).order_by("pk").values_list("pk", flat=True):
            if pk == candidate:
                candidate += 1
            elif pk > candidate:
                break
        if candidate > MAX_PORTABLE_ID:
            raise ValidationError("No portable identities remain available.")
        instance.pk = candidate
        if args:
            args = (True, *args[1:])
        else:
            kwargs["force_insert"] = True
        try:
            return save(*args, **kwargs)
        except Exception:
            instance.pk = None
            raise


def normalize_domain(value):
    if not isinstance(value, str):
        raise ValidationError("Enter a qualified DNS domain.")
    value = value.strip().lower().removesuffix(".")
    if (
        len(value) > 253
        or "." not in value
        or any(not DNS_LABEL.fullmatch(label) for label in value.split("."))
    ):
        raise ValidationError("Enter a qualified DNS domain.")
    return value


def normalize_prefix(value):
    if not isinstance(value, str):
        raise ValidationError("Enter exactly two decimal IPv4 octets.")
    value = value.strip()
    octets = value.split(".")
    if len(octets) != 2 or any(
        not re.fullmatch(r"[0-9]{1,3}", octet) or int(octet) > 255
        for octet in octets
    ):
        raise ValidationError("Enter exactly two decimal IPv4 octets.")
    return ".".join(str(int(octet)) for octet in octets)


def normalize_mac(value):
    if not isinstance(value, str):
        raise ValidationError("Enter a valid MAC address.")
    value = value.strip().lower()
    if not value:
        return ""
    if value.endswith(";"):
        value = value[:-1].strip()
    patterns = (
        r"[0-9a-f]{12}",
        r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",
        r"(?:[0-9a-f]{2}-){5}[0-9a-f]{2}",
        r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}",
    )
    if not any(re.fullmatch(pattern, value) for pattern in patterns):
        raise ValidationError("Enter a valid MAC address.")
    digits = re.sub(r"[:.-]", "", value)
    if int(digits[:2], 16) & 1 or int(digits, 16) == 0:
        raise ValidationError("A MAC address must be nonzero and unicast.")
    return ":".join(digits[index:index + 2] for index in range(0, 12, 2))


class Configuration(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    lan_domain = models.CharField(max_length=253, default="intranet.example.tld")
    vpn_domain = models.CharField(max_length=253, default="vpn.example.tld")
    lan_prefix = models.CharField(max_length=7, default="192.168")
    vpn_prefix = models.CharField(max_length=7, default="172.28")
    gandi_zone = models.CharField(max_length=253, default="example.tld")
    gandi_token = models.CharField(max_length=512, blank=True, default="")
    ttl = models.PositiveIntegerField(
        default=300, validators=[MinValueValidator(1), MaxValueValidator(MAX_SERIAL)]
    )
    soa_ns = models.CharField(max_length=253, default="ns.example.tld")
    soa_mailbox = models.CharField(max_length=253, default="hostmaster.intranet.example.tld")
    soa_refresh = models.PositiveIntegerField(
        default=43200, validators=[MinValueValidator(1), MaxValueValidator(MAX_SERIAL)]
    )
    soa_retry = models.PositiveIntegerField(
        default=180, validators=[MinValueValidator(1), MaxValueValidator(MAX_SERIAL)]
    )
    soa_expire = models.PositiveIntegerField(
        default=1209600, validators=[MinValueValidator(1), MaxValueValidator(MAX_SERIAL)]
    )
    soa_minimum = models.PositiveIntegerField(
        default=10800, validators=[MinValueValidator(0), MaxValueValidator(MAX_SERIAL)]
    )
    zone_ns = models.CharField(max_length=253, default="ns.example.tld")
    dns_export_directory = models.CharField(max_length=4096, blank=True, default="")
    soa_serial = models.PositiveBigIntegerField(
        default=initial_serial, validators=[MinValueValidator(1), MaxValueValidator(MAX_SERIAL)]
    )
    dns_content_hash = models.CharField(max_length=64, blank=True, default="", editable=False)
    dns_nas_host = models.CharField(max_length=253, blank=True, default="")
    dns_nas_user = models.CharField(max_length=64, blank=True, default="")
    dns_nas_port = models.PositiveIntegerField(
        default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )
    dns_published_generation = models.CharField(max_length=32, blank=True, default="", editable=False)
    revision = models.PositiveBigIntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(MAX_SERIAL)]
    )

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(id=1), name="configuration_singleton"),
            models.CheckConstraint(
                condition=Q(revision__gte=1, revision__lte=MAX_SERIAL),
                name="configuration_serial_bounds",
            ),
            models.CheckConstraint(
                condition=Q(ttl__gte=1, ttl__lte=MAX_SERIAL),
                name="configuration_ttl_bounds",
            ),
            models.CheckConstraint(
                condition=Q(soa_serial__gte=1, soa_serial__lte=MAX_SERIAL),
                name="configuration_dns_serial_bounds",
            ),
        ]

    @classmethod
    def load(cls):
        return cls.objects.get_or_create(pk=1)[0]

    def clean(self):
        self.clean_for_hosts(Host.objects.all())

    def clean_for_hosts(self, hosts):
        errors = {}
        for field in ("lan_domain", "vpn_domain", "gandi_zone", "soa_ns", "soa_mailbox", "zone_ns"):
            try:
                setattr(self, field, normalize_domain(getattr(self, field)))
            except ValidationError as error:
                errors[field] = error.messages
        if self.dns_export_directory and (
            "\x00" in self.dns_export_directory or not Path(self.dns_export_directory).is_absolute()
        ):
            errors["dns_export_directory"] = "Enter an absolute directory on the dnsgrid host."
        from .dns_notify import validate_destination
        try:
            validate_destination(self.dns_nas_host, self.dns_nas_user, self.dns_nas_port)
        except ValidationError as error:
            errors["dns_nas_host"] = error.messages
        for field in ("lan_prefix", "vpn_prefix"):
            try:
                setattr(self, field, normalize_prefix(getattr(self, field)))
            except ValidationError as error:
                errors[field] = error.messages
        if not errors and not (
            self.vpn_domain == self.gandi_zone
            or self.vpn_domain.endswith("." + self.gandi_zone)
        ):
            errors["vpn_domain"] = "The VPN domain must belong to the Gandi zone."
        longest_name = max(
            (len(host.name) for host in hosts),
            default=0,
        )
        if longest_name:
            for field in ("lan_domain", "vpn_domain"):
                if field not in errors and longest_name + 1 + len(getattr(self, field)) > 253:
                    errors[field] = "Existing host names would exceed the DNS name length limit."
        if errors:
            raise ValidationError(errors)

    def __str__(self):
        return "DNS configuration"


class Site(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True)
    name = models.CharField(max_length=80)
    g = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(255)]
    )
    dsm_ifname = models.CharField(
        max_length=15, blank=True, default="",
        validators=[RegexValidator(
            r"\A[A-Za-z0-9_.-]+\Z", "Enter a DSM interface name such as ovs_eth0.",
        )],
    )

    class Meta:
        ordering = ["id"]
        constraints = [
            models.CheckConstraint(condition=Q(id__gte=1, id__lte=4), name="site_fixed_ids"),
            models.CheckConstraint(condition=Q(g__lte=255), name="site_octet_bounds"),
        ]

    def clean(self):
        self.name = self.name.strip() if isinstance(self.name, str) else ""
        if not self.name:
            raise ValidationError({"name": "Enter a site name."})

    def __str__(self):
        return self.name


VPN_SHORT_SUFFIX = "vpn"


class Host(models.Model):
    class Status(models.TextChoices):
        RUNNING = "running", "Running"
        DECOMMISSIONED = "decommissioned", "Decommissioned"
        UNCONFIRMED = "unconfirmed", "Unconfirmed"

    name = models.CharField(max_length=63, unique=True)
    site = models.ForeignKey(Site, on_delete=models.PROTECT, related_name="hosts")
    row = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(15)]
    )
    column = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(7)]
    )
    category = models.CharField(max_length=80, blank=True, default="")
    status = models.CharField(max_length=14, choices=Status.choices, default=Status.RUNNING)
    vpn = models.BooleanField(default=False)
    public_export = models.BooleanField(default=False)
    mac = models.CharField(max_length=17, blank=True, default="")
    notes = models.TextField(
        blank=True, default="", max_length=4000, validators=[MaxLengthValidator(4000)]
    )

    class Meta:
        ordering = ["column", "row"]
        constraints = [
            models.UniqueConstraint(fields=["row", "column"], name="host_unique_position"),
            models.UniqueConstraint(
                fields=["mac"], condition=~Q(mac=""), name="host_unique_nonempty_mac"
            ),
            models.CheckConstraint(condition=Q(row__lte=15), name="host_row_bounds"),
            models.CheckConstraint(condition=Q(column__lte=7), name="host_column_bounds"),
            models.CheckConstraint(condition=~Q(row=0, column=0), name="host_reserved_position"),
            models.CheckConstraint(
                condition=Q(status__in=["running", "decommissioned", "unconfirmed"]),
                name="host_status_choices",
            ),
        ]

    def clean_fields(self, exclude=None):
        if not exclude or "mac" not in exclude:
            try:
                self.mac = normalize_mac(self.mac)
            except ValidationError as error:
                raise ValidationError({"mac": error.messages}) from error
        super().clean_fields(exclude=exclude)

    def save(self, *args, **kwargs):
        return _save_portable_identity(self, super().save, *args, **kwargs)

    def clean(self):
        config = Configuration.objects.filter(pk=1).first() or Configuration()
        self.clean_for_inventory(config, Host.objects.exclude(pk=self.pk))

    def clean_for_inventory(self, config, hosts):
        errors = {}
        self.name = self.name.strip().lower() if isinstance(self.name, str) else ""
        if not DNS_LABEL.fullmatch(self.name):
            errors["name"] = "Enter a DNS label (letters, digits, and interior hyphens)."
        if any(
            len(self.name) + 1 + len(domain) > 253
            for domain in (config.lan_domain, config.vpn_domain)
        ):
            errors["name"] = "The host's LAN and VPN DNS names must not exceed 253 characters."
        try:
            self.mac = normalize_mac(self.mac)
        except ValidationError as error:
            errors["mac"] = error.messages
        if self.row == 0 and self.column == 0:
            errors["row"] = "Position (0, 0) is reserved."
        if self.mac and any(host.mac == self.mac for host in hosts):
            errors["mac"] = "This MAC address is already in use."
        if errors:
            raise ValidationError(errors)

    @property
    def x(self):
        return 16 * self.column + self.row

    def lan_address(self, config):
        return f"{config.lan_prefix}.{self.site.g}.{self.x}"

    def vpn_address(self, config):
        return f"{config.vpn_prefix}.{self.site.g}.{self.x}"

    def lan_fqdn(self, config):
        return f"{self.name}.{config.lan_domain}"

    def vpn_fqdn(self, config):
        return f"{self.name}.{config.vpn_domain}"

    @property
    def vpn_short_name(self):
        return f"{self.name}.{VPN_SHORT_SUFFIX}"

    def __str__(self):
        return self.name


class GandiRecord(models.Model):
    zone = models.CharField(max_length=253)
    name = models.CharField(max_length=253)
    record_type = models.CharField(max_length=1, choices=[("A", "A")], default="A")
    values = models.JSONField(default=list)
    ttl = models.PositiveIntegerField(
        default=300, validators=[MinValueValidator(1), MaxValueValidator(MAX_SERIAL)]
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["zone", "name", "record_type"], name="gandi_unique_owned_record"
            ),
            models.CheckConstraint(condition=Q(record_type="A"), name="gandi_record_type"),
            models.CheckConstraint(
                condition=Q(ttl__gte=1, ttl__lte=MAX_SERIAL), name="gandi_ttl_bounds"
            ),
        ]

    def clean(self):
        self.zone = normalize_domain(self.zone)
        self.name = (
            self.name.strip().lower().removesuffix(".")
            if isinstance(self.name, str) else ""
        )
        if self.name != "@" and any(
            not DNS_LABEL.fullmatch(label) for label in self.name.split(".")
        ):
            raise ValidationError({"name": "Enter a DNS record name."})
        if not isinstance(self.values, list) or any(
            not isinstance(value, str) for value in self.values
        ):
            raise ValidationError({"values": "Record values must be a list of strings."})

    def save(self, *args, **kwargs):
        return _save_portable_identity(self, super().save, *args, **kwargs)

    def __str__(self):
        return f"{self.name}.{self.zone} {self.record_type}"
