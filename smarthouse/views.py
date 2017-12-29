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
from smarthouse.models import Agent, House, HouseGallery, Booking, Payment, ContactUs


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


class WebsiteIndexView(ListView):
    template_name = 'site/index.html'
    paginate_by = 10
    model = House
    context_object_name = 'house_posts'

    def get_queryset(self):
        return self.model.objects.filter(is_published=True, is_available=True)


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


class SearchView(TemplateView):
    template_name = 'site/index.html'

    def post(self, request, *args, **kwargs):
        location = request.POST.get('location', '')
        low_limit = request.POST.get('low_limit', '')
        high_limit = request.POST.get('high_limit', '')
        queryset = None
        if location != '' and low_limit == '' and high_limit == '':
            queryset = Q(location__icontains=location)

        if location != '' and low_limit != '' and high_limit != '':
            queryset = (
                Q(ocation__icontains=location) and
                (Q(rent_price__lte=low_limit, rent_price__gte=high_limit) |
                 Q(sale_price__lte=low_limit, sale_price__gte=high_limit))
            )
        if location == '' and low_limit != '' and high_limit != '':
            queryset = (
                Q(rent_price__lte=low_limit, rent_price__gte=high_limit) |
                Q(sale_price__lte=low_limit, sale_price__gte=high_limit)
            )

        houses = House.objects.filter(queryset) \
            .exclude(is_published=False, is_available=False) \
            .distinct()

        print houses

        return HttpResponse("found")


class Checkout(TemplateView):
    template_name = 'site/checkout.html'

    def get_context_data(self, **kwargs):
        context = super(Checkout, self).get_context_data(**kwargs)
        house = get_object_or_404(House, pk=self.kwargs['pk'])
        context['house'] = house
        return context

    def post(self, request, *args, **kwargs):
        """This should be done on successful payment
        doing it here now for demo purposes
        """
        user = request.user
        try:
            house = House.objects.get(id=request.POST.get('id'))
            booking = Booking.objects.create(
                house=house,
                booked_by=user,
                deposit_amount=request.POST.get('deposit_amount')
            )
            booking.save()
            messages.success(request, "Your booking was placed successfully.")
            return HttpResponseRedirect('/')
        except House.DoesNotExist as e:
            messages.error(request, "Could not find the house requested try again later")
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

