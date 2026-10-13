from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("inventory", "0011_configuration_bind_paths")]

    operations = [
        migrations.AddField(
            model_name="host", name="static", field=models.BooleanField(default=False),
        ),
    ]
