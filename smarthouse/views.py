# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json

from django.conf.global_settings import DEFAULT_FROM_EMAIL
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.messages.views import SuccessMessageMixin
from django.core import serializers
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db import IntegrityError
from django.db.models import Q
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.shortcuts import render, get_object_or_404
# Create your views here.
from django.template import loader
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView, RedirectView, ListView, DetailView
from django.views.generic.edit import DeleteView, UpdateView
from django.urls import reverse
from smarthouse.models import Agent, House, HouseGallery, Booking, Payment, ContactUs, HouseOwner
from smarthouse.phone_number import CleanPhoneNumber
from smarthouse.signals import checkout_completed, checkout_failed
from smarthouse.AfricasTalkingGateway import AfricasTalkingGateway, AfricasTalkingGatewayException
from django.conf import settings


class CreateAccountView(TemplateView):
    template_name = 'site/signup.html'

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return HttpResponseRedirect('/')
        return render(request, self.template_name, {})

    def post(self, request, *args, **kwargs):
        try:

            account_type = request.POST.get('account_type')

            if account_type == 'house_owner':
                user = User.objects.create(
                    username=request.POST.get('username'),
                    email=request.POST.get('email'),
                    first_name=request.POST.get('first_name'),
                    last_name=request.POST.get('last_name'),
                )
                user.set_password(request.POST.get('password'))
                user.is_staff = True
                user.save()
                owner = HouseOwner.objects.create(
                    user=user,
                    phone_number=request.POST.get('phone_number1')
                )
                owner.save()
                login(request, user)
                messages.success(request, "Account created successfully")
                return HttpResponseRedirect(reverse("smarthouse:dashboard_index"))

            if account_type == 'agent':
                user = User.objects.create(
                    username=request.POST.get('username'),
                    email=request.POST.get('email'),
                    first_name=request.POST.get('first_name'),
                    last_name=request.POST.get('last_name'),
                )
                user.set_password(request.POST.get('password'))
                user.save()
                agent = Agent.objects.create(
                    user=user,
                    agency_name=request.POST.get('agency_name'),
                    phone_number=request.POST.get('phone_number')
                )
                agent.save()
                return HttpResponseRedirect(reverse("smarthouse:dashboard_index"))

            if account_type == 'client':
                user = User.objects.create(
                    username=request.POST.get('username'),
                    email=request.POST.get('email'),
                    first_name=request.POST.get('first_name'),
                    last_name=request.POST.get('last_name'),
                )
                user.set_password(request.POST.get('password'))
                user.save()
                return HttpResponseRedirect(reverse("smarthouse:web_index"))

        except IntegrityError:
            messages.info(request, "User account already exists please choose a different username")
            return HttpResponseRedirect("/singup")


class LoginView(View):
    template_name = 'site/login.html'

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        else:
            return render(request, self.template_name, {})

    def post(self, request, *args, **kwargs):
        next_url = request.GET.get('next', '')
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            is_agent = Agent.objects.filter(user=user).exists()

            if (is_agent or user.is_staff) and next_url == '':
                return HttpResponseRedirect('/dashboard')

            elif next_url != '':
                return HttpResponseRedirect(next_url)
            else:
                return HttpResponseRedirect('/')
        else:
            message = 'invalid username or password'
            return render(request, self.template_name, {'error': message})


class LogoutView(RedirectView):
    url = '/login'

    def get(self, request, *args, **kwargs):
        logout(request)
        return super(LogoutView, self).get(request, *args, **kwargs)


class ResetPasswordRequestView(TemplateView):
    template_name = 'registration/forgot_password.html'

    @staticmethod
    def validate_email_address(email):
        try:
            validate_email(email)
            return True
        except ValidationError:
            return False

    def post(self, request, *args, **kwargs):
        email = request.POST.get('email', '')
        if self.validate_email_address(email) is True:
            user_exists = User.objects.filter(email=email)[:1].exists()
            if user_exists:
                user = User.objects.get(email=email)
                c = {
                    'email': user.email,
                    'domain': request.META['HTTP_HOST'],
                    'site_name': 'SmartKeja',
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'user': user,
                    'token': default_token_generator.make_token(user),
                    'protocol': 'http',
                }
                subject_template_name = 'registration/password_reset_subject.txt'
                email_template_name = 'registration/password_reset_email.html'
                subject = loader.render_to_string(subject_template_name, c)
                subject = ''.join(subject.splitlines())
                email_message = loader.render_to_string(email_template_name, c)
                send_mail(subject, email_message, DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
                messages.success(request, "Password reset link sent to %s check your inbox "
                                          "if not there check in the spam folder" % user.email)
                return HttpResponseRedirect(reverse("smarthouse:login"))
            else:
                messages.info(request, 'No matching account with the email provided please try again later')
                return HttpResponseRedirect("smarthouse:forgot_password")
        else:
            messages.info(request, "Please enter a valid email")
            return HttpResponseRedirect('/forgot-password/')


class PasswordResetConfirmView(TemplateView):
    template_name = 'registration/reset_password_confirm.html'

    def post(self, request, uidb64=None, token=None, *args, **kwargs):
        UserModel = get_user_model()
        assert uidb64 is not None and token is not None

        try:
            uid = urlsafe_base64_decode(uidb64)

            user = UserModel._default_manager.get(pk=uid)

        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist) as e:
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            new_password = request.POST.get('confirm', '')
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Password reset was successful use the new password to login')
            return HttpResponseRedirect('/login/')
        else:
            messages.info(request, 'Encountered an error while resetting your password please try again later')
            return HttpResponseRedirect('/reset-password-confirm/{}-{}/'.format(uidb64, token))


class HousePostListView(ListView):
    paginate_by = 10
    paginate_orphans = 3
    context_object_name = 'houses'
    model = House
    template_name = 'houses_list.html'


class HouseDetailView(DetailView):
    model = House
    template_name = 'site/house_details.html'
    context_object_name = 'house'

    def get_context_data(self, **kwargs):
        context = super(HouseDetailView, self).get_context_data(**kwargs)

        try:
            gallery = HouseGallery.objects.get(house=get_object_or_404(House, pk=self.kwargs['pk']))

        except HouseGallery.DoesNotExist:
            gallery = None

        context['gallery'] = gallery
        return context


class DeleteHouseView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    login_url = '/login'
    template_name = 'dashboard/pages/delete_house.html'
    context_object_name = 'house'
    success_url = '/dashboard/myposts/'
    model = House
    success_message = 'House Was deleted'


class UpdateHouseView(LoginRequiredMixin, SuccessMessageMixin, TemplateView):
    template_name = 'dashboard/pages/update_house.html'
    login_url = '/login'
    success_message = 'House Info updated'

    def get_context_data(self, **kwargs):
        context = super(UpdateHouseView, self).get_context_data(**kwargs)
        house = get_object_or_404(House, pk=self.kwargs['pk'])
        context['house'] = house
        return context

    def post(self, request, *args, **kwargs):
        house = get_object_or_404(House, pk=self.kwargs['pk'])
        posting_for = request.POST.get('posting_for')
        if posting_for == 'sale':
            house.sale_price = request.POST.get('id_sale_price')
            house.rent_price = 0
            house.on_sale = True

        if posting_for == 'rent':
            house.sale_price = 0
            house.rent_price = request.POST.get('id_rent_price')
            house.on_sale = False

        house.bedrooms = request.POST.get('bedrooms')

        house.save()
        messages.success(request, "House info updated successfully")
        return HttpResponseRedirect(reverse("smarthouse:myposts"))


class PostHouseView(LoginRequiredMixin, TemplateView):
    login_url = '/login'
    template_name = 'dashboard/pages/post_house.html'

    def post(self, request, *args, **kwargs):
        if request.user.is_active:
            if request.FILES.__contains__('primary_img'):
                posting_for = request.POST.get('posting_for')

                house = House.objects.create(
                    managed_by=request.user,
                    lat=request.POST.get('lat'),
                    lng=request.POST.get('lng'),
                    location=request.POST.get('location'),
                    bedrooms=request.POST.get('bedrooms'),
                    primary_img=request.FILES['primary_img'],
                    sale_price=0,
                    rent_price=0
                )

                if posting_for == 'sale':
                    house.sale_price = request.POST.get('id_sale_price')
                    house.rent_price = 0
                    house.on_sale = True

                if posting_for == 'rent':
                    house.sale_price = 0
                    house.rent_price = request.POST.get('id_rent_price')
                    house.on_sale = False

                house.save()
                messages.success(request, "House Posted Successfully")
                return HttpResponseRedirect(reverse('smarthouse:myposts'))
            else:
                messages.info(request, "An image is required")
                return HttpResponseRedirect("")

        else:
            messages.info(request, "You are not authorized to post a house please contact "
                                   "admin to get your account activated")
            return HttpResponseRedirect("")


class UpdateGalleryView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    model = HouseGallery
    context_object_name = 'gallery'
    fields = ['image1', 'image2', 'image3', 'image4', 'image5']
    success_message = 'Gallery Updated'
    success_url = '/dashboard/myposts'
    template_name = 'dashboard/pages/add_images.html'
    login_url = '/login/'

    def get_object(self, queryset=None):
        obj, created = HouseGallery.objects.get_or_create(
            house=House.objects.get(pk=self.kwargs['pk']),

        )
        return obj


class DashboardIndex(LoginRequiredMixin, TemplateView):
    login_url = '/login'
    template_name = 'dashboard/index.html'

    def get_stats(self):
        stats = {}
        booked_houses = House.objects.filter(managed_by=self.request.user, is_available=False).count()
        total_houses = House.objects.filter(managed_by=self.request.user).count()
        vacant_houses = House.objects.filter(managed_by=self.request.user, is_available=True).count()
        unpublished_houses = House.objects.filter(managed_by=self.request.user, is_published=False).count()
        stats['booked_houses'] = booked_houses
        stats['total_houses'] = total_houses
        stats['vacant_houses'] = vacant_houses
        stats['unpublished_houses'] = unpublished_houses
        return stats

    def get_context_data(self, **kwargs):
        context = super(DashboardIndex, self).get_context_data(**kwargs)
        context.update(self.get_stats())
        return context


class WebsiteIndexView(ListView):
    template_name = 'site/index.html'
    paginate_by = 10
    model = House
    context_object_name = 'house_posts'

    def get_queryset(self):
        return self.model.objects.filter(is_published=True)


class MyHousePostsView(LoginRequiredMixin, ListView):
    login_url = '/login'
    template_name = 'dashboard/pages/myhouses.html'
    paginate_by = 10
    context_object_name = 'house_posts'

    def get_queryset(self):
        object_list = House.objects.filter(managed_by=self.request.user)
        return object_list


class PublishPost(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(PublishPost, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        house = get_object_or_404(House, pk=self.kwargs['pk'])
        data = json.loads(request.body)
        publish_value = data['publish_value']
        message = ''
        if publish_value == "on":
            message = 'House Published its now visible to clients'
            house.is_published = True
        if publish_value == 'off':
            message = "House Unpublished now its invisible to clients"
            house.is_published = False
        house.save()
        return JsonResponse({'message': message, 'status': 'success', 'status_code': 200})


class MyClientHouseBookingView(LoginRequiredMixin, ListView):
    # paginate_by = 10
    template_name = 'dashboard/pages/myhousebookings.html'
    model = Booking
    context_object_name = 'bookings'
    login_url = '/login'

    def get_queryset(self):
        return self.model.objects.filter(house__managed_by=self.request.user)


class MyClientHousePaymentView(LoginRequiredMixin, ListView):
    template_name = 'dashboard/pages/client_payments.html'
    model = Payment
    login_url = '/login'
    context_object_name = 'payments'

    def get_queryset(self):
        return self.model.objects.filter(
            house__managed_by=self.request.user,
            status__iexact='success'
        )


class SearchAdminView(MyHousePostsView):
    def get_queryset(self):
        object_list = []
        query = self.request.GET.get('q')
        if query:
            queryset = (Q(location__icontains=query))

            object_list = House.objects.filter(queryset).distinct().exclude(
                ~Q(managed_by__username=self.request.user.username)
            )
        return object_list

    def get_context_data(self, **kwargs):
        context = super(SearchAdminView, self).get_context_data(**kwargs)
        context['in_search'] = True
        if len(self.get_queryset()) > 0:
            context['results_found'] = True
        else:
            context['results_found'] = False

        context['house_posts'] = self.get_queryset()
        context['query'] = self.request.GET.get('q', '')

        return context


class SearchView(ListView):
    template_name = 'site/index.html'
    model = House

    def get_queryset(self):
        location = self.request.GET.get('location', '')
        low_price = self.request.GET.get('low_price')
        high_price = self.request.GET.get('high_price')
        houses = []
        if high_price and low_price:
            queryset = (
                Q(location__icontains=location) and
                Q(sale_price__gte=low_price, sale_price__lte=high_price) |
                Q(rent_price__gte=low_price, rent_price__lte=high_price)
            )

            houses = House.objects.filter(queryset).distinct()
        elif location == 'any' and not low_price and not high_price:
            houses = House.objects.all().distinct()
        elif location == 'any' and high_price and low_price:

            queryset = (
                Q(sale_price__gte=low_price, sale_price__lte=high_price) |
                Q(rent_price__gte=low_price, rent_price__lte=high_price)
            )

            houses = House.objects.filter(queryset).distinct()
        else:

            queryset = (
                Q(location__icontains=location)
            )
            houses = House.objects.filter(queryset).distinct()

        return houses

    def get_context_data(self, **kwargs):
        context = super(SearchView, self).get_context_data(**kwargs)
        context['search_results'] = self.get_queryset()
        context['count'] = 0
        if len(self.get_queryset()) > 0:
            context['results_found'] = True
            context['count'] = len(self.get_queryset())
        else:
            context['results_found'] = False
        context['in_search'] = True

        return context


class Checkout(TemplateView):
    template_name = 'site/checkout.html'

    def get_context_data(self, **kwargs):
        context = super(Checkout, self).get_context_data(**kwargs)
        house = get_object_or_404(House, pk=self.kwargs['pk'])
        context['house'] = house
        return context

    def post(self, request, *args, **kwargs):

        gateway = AfricasTalkingGateway(settings.USERNAME, settings.API_KEY)
        try:
            metadata = {"checkoutType": "Rent",
                        "houseId": request.POST.get('house_id'),
                        "username": request.user.username
                        }
            phone_number = CleanPhoneNumber(request.POST.get('phone_number')).validate_phone_number()
            house = House.objects.get(id=request.POST.get('house_id'))

            transactionId = gateway.initiateMobilePaymentCheckout(settings.PRODUCT_NAME,
                                                                  phone_number,
                                                                  settings.CURRENCY_CODE,
                                                                  request.POST.get('amount'),
                                                                  metadata
                                                                  )
            if transactionId:
                payment = Payment.objects.create(
                    txn_id=transactionId,
                    phone_number=phone_number,
                    amount=request.POST.get('amount'),
                    house=house,
                    status="Pending",
                    payment_type="Rent"
                )
                payment.save()
                messages.success(request, "Your request submitted check your phone to complete the transaction .")
                return HttpResponseRedirect('/')
            else:
                messages.info(request, "Unable to process your request")
                return HttpResponseRedirect('/')

        except (House.DoesNotExist, AfricasTalkingGatewayException) as e:
            messages.error(request, "Error occurred {}".format(e))
            return HttpResponseRedirect('/')


class AboutView(TemplateView):
    template_name = 'site/about.html'


class ContactUsView(TemplateView):
    template_name = 'site/contactus.html'

    def post(self, request, *args, **kwargs):
        name = request.POST.get('name', '')
        email = request.POST.get('email', '')
        message = request.POST.get('message', '')
        contact = ContactUs.objects.create(
            name=name,
            message=message,
            email=email
        )
        contact.save()
        messages.success(request, "Message sent successfully")
        return HttpResponseRedirect(reverse("smarthouse:web_index"))


class MapDataView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        houses = House.objects.filter(managed_by=self.request.user)
        # boards = Board.objects.all()
        return HttpResponse(serializers.serialize('json', houses), content_type='application/json')


class MapView(LoginRequiredMixin, TemplateView):
    login_url = '/login'
    template_name = 'dashboard/pages/map_view.html'


class MpesaNotificationHandler(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(MpesaNotificationHandler, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):

        data = json.loads(request.body)
        if data['status'].lower() == "success" and data['category'] == 'MobileCheckout':
            # create a booking here.
            house = get_object_or_404(House, id=data["requestMetadata"]["houseId"])

            if data["requestMetadata"]["checkoutType"].lower() == "rent":
                Booking.objects.get_or_create(
                    house=house,
                    booked_by=data["source"],
                    deposit_amount=float(data['value'][3:])
                )

                house.is_available = False
                house.save()
                checkout_completed.send(
                    sender=self.__class__,
                    txn_id=data['transactionId'],
                    status=data['status']
                )
                return HttpResponse("successful")
        elif data['status'].lower() != "success" and data['category'] == 'MobileCheckout':
            checkout_failed.send(
                sender=self.__class__,
                txn_id=data['transactionId'],
                status=data['status']
            )
            return HttpResponse("Failed")


@csrf_exempt
def ussd_test(request):
    if request.method == 'POST':
        sessionId = request.POST["sessionId"]
        serviceCode = request.POST["serviceCode"]
        phoneNumber = request.POST["phoneNumber"]
        text = request.POST["text"]
        new_res = text.rsplit("*")
        response = ''

        if text == "":
            response = "CON Welcome To Smart Keja \nPlease reply with \n"
            response += "1. House to rent\n"
            response += "2. House to buy\n"
            response += "0. Exit"
        if text == "1":
            response = "CON Enter your preferred house location"
        if text == "2":
            response = "END Sorry! this service is not available on USSD  \n" \
                       " Visit smartkeja.herokuapp.com To use this service"
        if text == "0":
            response = "END Thank you for using SmartKeja.You can also find us on smartkeja.herokuapp.com " \
                       "for more exciting services"

        if len(new_res) == 2 and text != "":
            location = new_res[1]
            response = "CON Please Reply with \n"
            houses = House.objects.filter(is_available=True, on_sale=False, location__icontains=location)

            if len(houses) == 0:
                response = "END No house matches your search try again later"

            for house in houses:
                response += "{}: {} Bedroom House in {} for KSH {}\n".format(house.id, house.bedrooms, house.location,
                                                                             house.rent_price)
        if len(new_res) == 3 and text != "":
            house = House.objects.get(id=int(new_res[2]))
            request.session['house_id'] = house.id
            response += "CON Please Reply with\n"
            response += "1: Confirm Your booking\n"
            response += "2: Cancel\n"

        if len(new_res) == 4 and text != "" and new_res[3] == "1":
            house = House.objects.get(id=new_res[2])

            gateway = AfricasTalkingGateway(settings.USERNAME, settings.API_KEY)
            try:
                metadata = {"checkoutType": "Rent",
                            "houseId": house.id,
                            "username": "userid"
                            }
                phone_number = CleanPhoneNumber(phoneNumber).validate_phone_number()
                amount = 300

                transactionId = gateway.initiateMobilePaymentCheckout(settings.PRODUCT_NAME,
                                                                      phoneNumber,
                                                                      settings.CURRENCY_CODE,
                                                                      amount,
                                                                      metadata
                                                                      )
                if transactionId:
                    payment = Payment.objects.create(
                        txn_id=transactionId,
                        phone_number=phone_number,
                        amount=house.rent_price,
                        house=house,
                        status="Pending",
                        payment_type="Rent"
                    )
                    payment.save()
                    response = "END Your request submitted check your phone to complete the transaction"

                else:
                    response = "END Unable to process your request"

            except AfricasTalkingGatewayException, e:
                response = "END Internal Error Occurred {}".format(str(e))

        if len(new_res) == 4 and text != "" and new_res[3] == "2":
            response = "END Thank you for using SmartKeja Services"

        return HttpResponse(response, content_type='text/plain')
