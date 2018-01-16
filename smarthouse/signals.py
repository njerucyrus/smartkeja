from __future__ import unicode_literals
from django.dispatch import Signal

checkout_completed = Signal(providing_args=['txn_id', 'status'])
checkout_failed = Signal(providing_args=['txn_id', 'status'])
