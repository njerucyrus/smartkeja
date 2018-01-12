# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User
from django.urls import reverse

# Create your models here.


class Agent(models.Model):
    user = models.OneToOneField(User)
    agency_name = models.CharField(max_length=100, )
    phone_number = models.CharField(max_length=13, )

    def __str__(self):
        return self.agency_name


class HouseOwner(models.Model):
    user = models.OneToOneField(User)
    phone_number = models.CharField(max_length=13, )


class House(models.Model):
    managed_by = models.ForeignKey(User)
    lat = models.FloatField()
    lng = models.FloatField()
    location = models.CharField(max_length=200)
    rent_price = models.FloatField()
    sale_price = models.FloatField()
    bedrooms = models.IntegerField()
    description = models.TextField()
    on_sale = models.BooleanField(default=False)
    is_available = models.BooleanField(default=True)
    primary_img = models.ImageField(upload_to='uploads/')
    is_published = models.BooleanField(default=False)
    date_posted = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-date_posted', )

    def get_absolute_url(self):
        return reverse('smarthouse:house_detail', args=[self.pk])

    def __str__(self):
        return "A {}-bedroom(s) House at {}".format(self.bedrooms, self.location)


class HouseGallery(models.Model):
    house = models.ForeignKey(House)
    image1 = models.ImageField(upload_to='uploads/', null=True, blank=True)
    image2 = models.ImageField(upload_to='uploads/', null=True, blank=True)
    image3 = models.ImageField(upload_to='uploads/', null=True, blank=True)
    image4 = models.ImageField(upload_to='uploads/', null=True, blank=True)
    image5 = models.ImageField(upload_to='uploads/', null=True, blank=True)

    def __str__(self):
        return "Gallery for {}".format(str(self.house))


class Booking(models.Model):
    house = models.ForeignKey(House)
    booked_by = models.ForeignKey(User)
    date_booked = models.DateTimeField(auto_now_add=True)
    cleared = models.BooleanField(default=False)
    deposit_amount = models.FloatField()

    def __str__(self):
        return "Booking for {}".format(str(self.house))


class Payment(models.Model):
    txn_id = models.CharField(max_length=200)
    phone_number = models.CharField(max_length=13)
    amount = models.FloatField()
    house = models.ForeignKey(House)
    status = models.CharField(max_length=32)
    PAYMENT_TYPE_CHOICE = [
        ('Rent', 'Rent'),
        ('Purchase', 'Purchase')
    ]
    payment_type = models.CharField(max_length=20, choices=PAYMENT_TYPE_CHOICE, default=PAYMENT_TYPE_CHOICE[0][0])
    date_paid = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{} for {}".format(self.payment_type, str(self.house))


class ContactUs(models.Model):
    name = models.CharField(max_length=200)
    email = models.EmailField()
    message = models.TextField(max_length=200)

    def __str__(self):
        return "Contact message from {}".format(self.email)
