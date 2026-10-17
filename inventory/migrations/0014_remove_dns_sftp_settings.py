from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0013_dhcp_publications"),
    ]

    operations = [
        migrations.RemoveField(model_name="configuration", name="dns_sftp_host"),
        migrations.RemoveField(model_name="configuration", name="dns_sftp_user"),
        migrations.RemoveField(model_name="configuration", name="dns_sftp_port"),
        migrations.RemoveField(model_name="configuration", name="dns_sftp_inbox"),
        migrations.RemoveField(model_name="configuration", name="dns_sftp_outbox"),
    ]
