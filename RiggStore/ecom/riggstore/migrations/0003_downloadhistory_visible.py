# Generated by Django 5.1.7 on 2025-03-30 18:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('riggstore', '0002_order_games'),
    ]

    operations = [
        migrations.AddField(
            model_name='downloadhistory',
            name='visible',
            field=models.BooleanField(default=True),
        ),
    ]
