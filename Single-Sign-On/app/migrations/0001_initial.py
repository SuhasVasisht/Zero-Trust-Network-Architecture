# Generated by Django 2.2.10 on 2021-11-14 15:59

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Employee',
            fields=[
                ('name', models.CharField(max_length=200)),
                ('username', models.CharField(max_length=200)),
                ('uid', models.CharField(max_length=200, primary_key=True, serialize=False)),
            ],
        ),
    ]
