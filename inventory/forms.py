from django import forms

from .models import MAX_SERIAL, Host, Site, normalize_mac


class MACAddressField(forms.CharField):
    def to_python(self, value):
        return normalize_mac(super().to_python(value))


class HostForm(forms.Form):
    name = forms.CharField(max_length=63)
    site = forms.ModelChoiceField(queryset=Site.objects.order_by("id"))
    row = forms.IntegerField(min_value=0, max_value=15)
    column = forms.IntegerField(min_value=0, max_value=7)
    category = forms.CharField(max_length=80, required=False)
    status = forms.ChoiceField(choices=Host.Status.choices)
    vpn = forms.BooleanField(required=False, label="VPN member")
    public_export = forms.BooleanField(required=False, label="Publish on Gandi (VPN only)")
    mac = MACAddressField(max_length=32, required=False, label="MAC address")
    notes = forms.CharField(max_length=4000, required=False, widget=forms.Textarea(attrs={"rows": 3}))
    revision = forms.IntegerField(widget=forms.HiddenInput)


class HostMoveForm(forms.Form):
    direction = forms.ChoiceField(choices=(("up", "Move up"), ("down", "Move down")))
    revision = forms.IntegerField(widget=forms.HiddenInput)


class ArchiveUploadForm(forms.Form):
    archive = forms.FileField(label="Application archive (UTF-8 JSON, at most 8 MiB)")
    revision = forms.IntegerField(min_value=1, max_value=MAX_SERIAL, widget=forms.HiddenInput)


class ConfigurationForm(forms.Form):
    lan_domain = forms.CharField(max_length=253, label="LAN domain base")
    vpn_domain = forms.CharField(max_length=253, label="VPN domain base")
    lan_prefix = forms.CharField(max_length=7)
    vpn_prefix = forms.CharField(max_length=7)
    gandi_zone = forms.CharField(max_length=253, label="Gandi managed zone")
    gandi_token = forms.CharField(
        required=False, max_length=512, widget=forms.PasswordInput,
        help_text="Leave blank to keep the saved token. DNSGRID_GANDI_TOKEN overrides it.",
    )
    clear_token = forms.BooleanField(required=False, label="Remove saved Gandi token")
    ttl = forms.IntegerField(min_value=60, max_value=86400, label="DNS TTL (seconds)")
    soa_ns = forms.CharField(max_length=253, label="SOA primary nameserver FQDN")
    soa_mailbox = forms.CharField(max_length=253, label="SOA mailbox (DNS name, not email)")
    soa_refresh = forms.IntegerField(min_value=1, max_value=MAX_SERIAL, label="SOA refresh (seconds)")
    soa_retry = forms.IntegerField(min_value=1, max_value=MAX_SERIAL, label="SOA retry (seconds)")
    soa_expire = forms.IntegerField(min_value=1, max_value=MAX_SERIAL, label="SOA expire (seconds)")
    soa_minimum = forms.IntegerField(min_value=0, max_value=MAX_SERIAL, label="SOA negative-cache TTL (seconds)")
    zone_ns = forms.CharField(max_length=253, label="Zone NS nameserver FQDN")
    soa_serial = forms.IntegerField(
        min_value=1, max_value=MAX_SERIAL, label="SOA serial",
        help_text="UTC YYYYMMDDnn (00..99), upward only. DNS content changes advance it; previews and downloads do not.",
    )
    dns_export_directory = forms.CharField(
        max_length=4096, required=False, label="DNS export directory",
        help_text="Absolute existing directory on the dnsgrid host. Blank disables publication. Saving never writes files.",
    )
    revision = forms.IntegerField(widget=forms.HiddenInput)

    def __init__(self, *args, sites, **kwargs):
        super().__init__(*args, **kwargs)
        for site in sites:
            self.fields[f"site_{site.pk}_name"] = forms.CharField(
                max_length=80, label=f"Site {site.pk} name", initial=site.name,
            )
            self.fields[f"site_{site.pk}_g"] = forms.IntegerField(
                min_value=0, max_value=255, label=f"Site {site.pk} octet g", initial=site.g,
            )
            self.fields[f"site_{site.pk}_dsm_ifname"] = forms.CharField(
                max_length=15, required=False, label=f"Site {site.pk} DSM DHCP interface",
                initial=site.dsm_ifname,
                validators=Site._meta.get_field("dsm_ifname").validators,
                help_text="Optional; enables reservation API exports for this site's DSM server.",
            )
