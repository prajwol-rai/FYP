# Generated by Django 5.1.6 on 2025-03-18 18:41

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('riggstore', '0007_alter_gamescreenshot_game_submission'),
    ]

    operations = [
        migrations.AlterField(
            model_name='gamescreenshot',
            name='game_submission',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='riggstore.gamesubmission'),
        ),
    ]
