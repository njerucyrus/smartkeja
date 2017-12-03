# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf.global_settings import DEFAULT_FROM_EMAIL
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db import IntegrityError
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404

# Create your views here.
from django.template import loader
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views import View
from django.views.generic import TemplateView, RedirectView, ListView, DetailView

from smarthouse.models import Agent, House, HouseGallery


class CreateAccountView(TemplateView):
    template_name = 'signup.html'

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
                return HttpResponseRedirect('/dashboard')

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
                return HttpResponseRedirect('/dashboard')

            if account_type == 'client':
                user = User.objects.create(
                    username=request.POST.get('username'),
                    email=request.POST.get('email'),
                    first_name=request.POST.get('first_name'),
                    last_name=request.POST.get('last_name'),
                )
                user.set_password(request.POST.get('password'))
                user.save()
                return HttpResponseRedirect('/')

        except IntegrityError:
            messages.info(request, "User account already exists please choose a different username")
            return HttpResponseRedirect("")


class LoginView(View):
    template_name = 'website/pages/login.html'

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
                    'site_name': 'H-BOARD',
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
                return HttpResponseRedirect('/login/')
            else:
                messages.info(request, 'No matching account with the email provided please try again later')
                return HttpResponseRedirect('/forgot-password/')
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
    template_name = 'house_detail.html'

    def get_context_data(self,  **kwargs):
        context = super(HouseDetailView,self).get_context_data(**kwargs)

        try:
            gallery = HouseGallery.objects.get(house=get_object_or_404(House, pk=self.kwargs['pk']))

        except HouseGallery.DoesNotExist:
            gallery = None

        context['gallery'] = gallery
        return context


class PostHouseView(LoginRequiredMixin, TemplateView):
    login_url = '/login'

    def post(self, request, *args, **kwargs):
        if request.user.is_active:
            posting_for = request.POST.get('posting_for')

            house = House.objects.create(
                managed_by=request.user,
                lat=request.POST.get('lat'),
                lng=request.POST.get('lng'),
                location=request.POST.get('location'),
                bedrooms=request.POST.get('bedrooms')
            )

            if posting_for == 'sale':
                house.sale_price = request.POST.get('sale_price')
                house.rent_price = 0
                house.on_sale = True

            if posting_for == 'rent':
                house.sale_price = 0
                house.rent_price = request.POST.get('rent_price')
                house.on_sale = False

            house.save()
            messages.success(request, "House Posted Successfully")
            return HttpResponseRedirect('/houses')
        else:
            messages.info(request, "You are not authorized to post a house please contact "
                                   "admin to get your account activated")
            return HttpResponseRedirect("")



