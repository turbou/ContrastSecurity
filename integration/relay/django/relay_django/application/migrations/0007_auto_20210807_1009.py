# Generated by Django 2.2.13 on 2021-08-07 10:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('application', '0006_auto_20210806_0611'),
    ]

    operations = [
        migrations.AddField(
            model_name='redmine',
            name='severity_id_cvelib',
            field=models.PositiveIntegerField(blank=True, null=True, verbose_name='Vulnerable library ID'),
        ),
        migrations.AddField(
            model_name='redmine',
            name='severity_name_cvelib',
            field=models.CharField(default='重大', max_length=50, verbose_name='Vulnerable library'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='severity_name_critical',
            field=models.CharField(default='重大', max_length=50, verbose_name='Severity Critical'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='severity_name_high',
            field=models.CharField(default='高', max_length=50, verbose_name='Severity High'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='severity_name_low',
            field=models.CharField(default='低', max_length=50, verbose_name='Severity Low'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='severity_name_medium',
            field=models.CharField(default='中', max_length=50, verbose_name='Severity Medium'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='severity_name_note',
            field=models.CharField(default='注意', max_length=50, verbose_name='Severity Note'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='status_name_confirmed',
            field=models.CharField(default='確認済', max_length=50, verbose_name='Status Confirmed'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='status_name_fixed',
            field=models.CharField(default='修正完了', max_length=50, verbose_name='Status Fixed'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='status_name_notaproblem',
            field=models.CharField(default='問題無し', max_length=50, verbose_name='Status NotAProblem'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='status_name_remediated',
            field=models.CharField(default='修復済', max_length=50, verbose_name='Status Remediated'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='status_name_reported',
            field=models.CharField(default='報告済', max_length=50, verbose_name='Status Reported'),
        ),
        migrations.AlterField(
            model_name='redmine',
            name='status_name_suspicious',
            field=models.CharField(default='疑わしい', max_length=50, verbose_name='Status Suspicious'),
        ),
    ]
