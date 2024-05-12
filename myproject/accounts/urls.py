from django.urls import path
from . import views

urlpatterns = [
    # path('accounts/', include('accounts.urls')),
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    # path('forgot_password/', views.forgot_password_view, name='forgot_password')
]