# Generated by Django 2.2.13 on 2021-07-26 23:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('application', '0004_auto_20210721_0954'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='redmine',
            name='tracker',
        ),
    ]
