# Generated by Django 2.2.13 on 2020-11-11 03:18

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('application', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Integration',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='この名前をTeamServerのPayloadに設定してください。', max_length=20, unique=True, validators=[django.core.validators.RegexValidator(message='名前は半角英数字、アンスコ4文字〜10文字です。', regex='^[A-Za-z0-9_]{4,20}$')], verbose_name='名前')),
                ('url', models.URLField(help_text='e.g. https://app.contrastsecurity.com/Contrast', verbose_name='TeamServer URL')),
                ('api_key', models.CharField(max_length=50, unique=True, verbose_name='API Key')),
                ('username', models.CharField(help_text='Login ID (mail address)', max_length=20, unique=True, verbose_name='Username')),
                ('service_key', models.CharField(max_length=20, unique=True, verbose_name='Service Key')),
                ('backlog', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='integrations', related_query_name='integration', to='application.Backlog', verbose_name='Backlog')),
                ('gitlab', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='integrations', related_query_name='integration', to='application.Gitlab', verbose_name='Gitlab')),
                ('googlechat', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='integrations', related_query_name='integration', to='application.GoogleChat', verbose_name='GoogleChat')),
            ],
            options={
                'verbose_name': 'Integration設定',
                'verbose_name_plural': 'Integration設定一覧',
            },
        ),
    ]
