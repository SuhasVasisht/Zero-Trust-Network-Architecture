# Generated by Django 2.2.10 on 2021-10-24 14:43

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Resources',
        ),
        migrations.DeleteModel(
            name='User',
        ),
    ]
