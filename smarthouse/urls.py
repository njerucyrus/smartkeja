from django.conf.urls import url

from . import views

urlpatterns = [
    # url(r'$', views.WebsiteIndexView.as_view(), name='web_index'),
    url(r'dashboard/$', views.DashboardIndex.as_view(), name='dashboard_index'),
    url(r'login/$', views.LoginView.as_view(), name='login'),
    url(r'signup/$', views.CreateAccountView.as_view(), name='signup'),
    url(r'^logout/$', views.LogoutView.as_view(), name='logout'),
    url(r'^forgot-password/$', views.ResetPasswordRequestView.as_view(), name='forgot_password'),
    url(r'^reset_password_confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$', views.PasswordResetConfirmView.as_view(),
        name='reset_password_confirm'),
    url(r'dashboard/posthouse/$', views.PostHouseView.as_view(), name='post_house'),
    url(r'dashboard/myposts/$', views.MyHousePostsView.as_view(), name='myposts'),
    url(r'dashboard/myposts/(?P<pk>\d+)/delete/$', views.DeleteHouseView.as_view(), name='delete_house'),
    url(r'dashboard/myposts/(?P<pk>\d+)/update/$', views.UpdateHouseView.as_view(), name='update_house'),
    url(r'dashboard/booking/$', views.MyHouseBookingView.as_view(), name='my_house_booking'),
    url(r'dashboard/myposts/(?P<pk>\d+)/update_gallery/$', views.UpdateGalleryView.as_view(), name='update_gallery'),
    url(r'api/(?P<pk>\d+)/publish/$', views.PublishPost.as_view(), name='publish')
]
