# Generated by Django 5.1.6 on 2025-03-28 21:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('riggstore', '0016_alter_customer_email'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customer',
            name='email',
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]
