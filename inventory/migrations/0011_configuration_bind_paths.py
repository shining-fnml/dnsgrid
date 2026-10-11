from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0010_unix_timestamp_serial_bounds"),
    ]

    operations = [
        migrations.AddField(
            model_name="configuration",
            name="named_checkzone",
            field=models.CharField(blank=True, default="", max_length=4096),
        ),
        migrations.AddField(
            model_name="configuration",
            name="rndc",
            field=models.CharField(blank=True, default="", max_length=4096),
        ),
        migrations.AddField(
            model_name="configuration",
            name="rndc_key",
            field=models.CharField(blank=True, default="", max_length=4096),
        ),
    ]
