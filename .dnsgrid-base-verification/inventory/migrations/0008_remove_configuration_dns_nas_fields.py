from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0007_configuration_dns_content_hash_and_more"),
    ]

    operations = [
        migrations.RemoveField(model_name="configuration", name="dns_nas_host"),
        migrations.RemoveField(model_name="configuration", name="dns_nas_user"),
        migrations.RemoveField(model_name="configuration", name="dns_nas_port"),
    ]
