# Generated by Django 5.1.6 on 2025-03-15 17:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('riggstore', '0004_remove_gamesubmission_category_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='game',
            name='category',
        ),
        migrations.AddField(
            model_name='game',
            name='categories',
            field=models.ManyToManyField(to='riggstore.category'),
        ),
    ]
