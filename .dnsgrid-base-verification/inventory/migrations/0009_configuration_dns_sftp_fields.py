import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0008_remove_configuration_dns_nas_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuration", name="dns_sftp_host",
            field=models.CharField(blank=True, default="", max_length=253),
        ),
        migrations.AddField(
            model_name="configuration", name="dns_sftp_user",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="configuration", name="dns_sftp_port",
            field=models.PositiveIntegerField(default=22, validators=[
                django.core.validators.MinValueValidator(1),
                django.core.validators.MaxValueValidator(65535),
            ]),
        ),
        migrations.AddField(
            model_name="configuration", name="dns_sftp_inbox",
            field=models.CharField(blank=True, default="", max_length=4096),
        ),
        migrations.AddField(
            model_name="configuration", name="dns_sftp_outbox",
            field=models.CharField(blank=True, default="", max_length=4096),
        ),
    ]
