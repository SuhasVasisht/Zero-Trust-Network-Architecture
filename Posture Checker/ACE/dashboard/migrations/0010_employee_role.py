# Generated by Django 2.2.10 on 2021-11-13 10:35

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0009_auto_20211024_1748'),
    ]

    operations = [
        migrations.CreateModel(
            name='Role',
            fields=[
                ('role', models.CharField(max_length=200, primary_key=True, serialize=False)),
                ('aceAdminDashboard', models.BooleanField(default=False)),
                ('codebase', models.BooleanField(default=False)),
                ('customerDatabase', models.BooleanField(default=False)),
                ('financialRecords', models.BooleanField(default=False)),
                ('employeeRecords', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Employee',
            fields=[
                ('name', models.CharField(max_length=200)),
                ('username', models.CharField(max_length=200, primary_key=True, serialize=False)),
                ('role', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to='dashboard.Role')),
            ],
        ),
    ]