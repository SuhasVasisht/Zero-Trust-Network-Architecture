# Generated by Django 2.2.10 on 2021-10-24 17:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0008_test6_os_versions'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='test1_network_applications',
            name='author',
        ),
        migrations.RemoveField(
            model_name='test2_flagged_browser_extensions',
            name='author',
        ),
    ]
