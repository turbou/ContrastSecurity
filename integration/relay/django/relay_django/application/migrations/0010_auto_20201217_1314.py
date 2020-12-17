# Generated by Django 2.2.13 on 2020-12-17 13:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('application', '0009_backlog_project_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='backlog',
            name='status_confirmed',
            field=models.CharField(default='', max_length=50, verbose_name='Confirmed'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_confirmed_id',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='Confirmed ID'),
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_fixed',
            field=models.CharField(default='', max_length=50, verbose_name='Fixed'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_fixed_id',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='Fixed ID'),
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_notaproblem',
            field=models.CharField(default='', max_length=50, verbose_name='Not a Problem'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_notaproblem_id',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='Not a Problem ID'),
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_remediated',
            field=models.CharField(default='', max_length=50, verbose_name='Remediated'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_remediated_id',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='Remediated ID'),
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_reported',
            field=models.CharField(default='', max_length=50, verbose_name='Reported'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_reported_id',
            field=models.CharField(blank=True, max_length=10, null=True, verbose_name='Reported ID'),
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_suspicious',
            field=models.CharField(default='', max_length=50, verbose_name='Suspicious'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='backlog',
            name='status_suspicious_id',
            field=models.CharField(blank=True, max_length=10, null=True, verbose_name='Suspicious ID'),
        ),
    ]
