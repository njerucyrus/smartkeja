# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2017-12-03 17:16
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('smarthouse', '0003_auto_20171203_1947'),
    ]

    operations = [
        migrations.RenameField(
            model_name='booking',
            old_name='amount_paid',
            new_name='deposit_amount',
        ),
    ]