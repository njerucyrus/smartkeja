# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin

from smarthouse.models import *


class HouseAdmin(admin.ModelAdmin):
    list_display = [
        'managed_by',
        'lat',
        'lng',
        'location',
        'rent_price',
        'sale_price',
        'bedrooms',
        'on_sale',
        'is_available',
        'primary_img',
    ]

    class Meta:
        model = House


admin.site.register(House, HouseAdmin)


class HouseGalleryAdmin(admin.ModelAdmin):
    list_display = [
        'house',
        'image1',
        'image2',
        'image3',
        'image4',
        'image5',
    ]

    class Meta:
        model = HouseGallery


admin.site.register(HouseGallery, HouseGalleryAdmin)


class BookingAdmin(admin.ModelAdmin):
    list_display = [
        'house',
        'booked_by',
        'deposit_amount',
        'cleared',
        'date_booked'
    ]

    class Meta:
        model = Booking


admin.site.register(Booking, BookingAdmin)


class PaymentAdmin(admin.ModelAdmin):
    list_display = [
        'txn_id',
        'phone_number',
        'amount',
        'house',
        'payment_type',
        'status',
        'date_paid'
    ]

    class Meta:
        model = Payment


admin.site.register(Payment, PaymentAdmin)


class AgentAdmin(admin.ModelAdmin):
    list_display = [
        'user',
        'agency_name',
        'phone_number'
    ]

    class Meta:
        model = Agent


admin.site.register(Agent, AgentAdmin)


class ContactUsAdmin(admin.ModelAdmin):
    list_display = [
        'name',
        "email",
        "message"
    ]
    model = ContactUs


admin.site.register(ContactUs, ContactUsAdmin)
