# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2017-12-03 21:24
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('smarthouse', '0004_auto_20171203_2016'),
    ]

    operations = [
        migrations.AddField(
            model_name='house',
            name='is_published',
            field=models.BooleanField(default=False),
        ),
    ]
