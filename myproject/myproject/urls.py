"""
URL configuration for myproject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
# from django.contrib.auth import views 
from accounts import views
from accounts.views import home_page
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
# from django.contrib.auth import views 
from accounts import views
from accounts.views import home_page
# from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
# from accounts.views import CustomPasswordResetView
from accounts.views import CustomPasswordResetView, CustomPasswordResetConfirmView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView  # Import TokenRefreshView
from django.http import JsonResponse

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('reset_password/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(template_name='accounts/password_reset_done.html'), name='password_reset_done'),  
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(template_name='accounts/password_reset_complete.html'), name='password_reset_complete'), 
    path('verify_email/', views.verify_email_request, name='verify_email_request'),
    path('verify_email/<uidb64>/<token>/', views.verify_email_confirm, name='verify_email_confirm'),
    path('',home_page,name='home'),
    path('forgot-password/', CustomPasswordResetView.as_view(), name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
