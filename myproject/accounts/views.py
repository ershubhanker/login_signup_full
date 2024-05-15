# # Create your views here.
from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .forms import ForgotPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.urls import reverse
from .models import Profile
from django.contrib import messages
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework_simplejwt.authentication import JWTTokenUser
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import status


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def protected_view(request):
    print(request.user.profile.user_type,request.user)
    return JsonResponse({"message": "You have accessed the protected view!"})


@login_required(login_url='login')
def home_page(request):
    print('\nchali\n')
    user_type = User.objects.get(username = request.user).profile.user_type
    # user_type = Profile.objects.get(user=user).user_type
    
    context = {'message':f'{request.user} {user_type}'}

    return render(request,'accounts/home.html',context=context)


UserModel = get_user_model()

def verify_email_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            print("in verify email func")
            user = UserModel.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(user.pk.to_bytes(4, 'big')).decode()
            token = default_token_generator.make_token(user)
            current_site = request.get_host()
            mail_subject = 'Verify your email address'
            message = render_to_string('accounts/email_verification_email.html', {
                'user': user,
                'domain': current_site,
                'uidb64': uidb64,
                'token': token,
            })
            send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [email])
            return render(request, 'accounts/verification_request.html')
        except UserModel.DoesNotExist:
            # Handle user not found
            pass
    return render(request, 'accounts/verify_email.html')


def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        user_type = request.POST.get('user_type')
        print(f'{username} {email} {password1} {password2} {user_type} ')
        
        user = User.objects.filter(username=username)
        
        if user.exists():
            messages.error(request, "username already exist.")
            return redirect('signup')
        
        if password1!=password2:
            messages.error(request, "password dosent matches")
            return redirect('signup')
        
        user = User.objects.create(
               username=username,
               email=email
        )
        
        user.set_password(password1)
        user.is_active = False
        user.save()
    
    
        # Send verification email
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        print(f"while signup the token is {token}")
        current_site = get_current_site(request)

        protocol = 'https' if request.is_secure() else 'http'  # Adjust protocol based on request
        # protocol = 'http' if request.is_secure() else 'https'  # Adjust protocol based on request
        domain = current_site.domain
        verify_url = reverse('verify_email_confirm', kwargs={'uidb64': uidb64, 'token': token})
        verification_link = f"{protocol}://{domain}{verify_url}"
        mail_subject = 'Activate your account'
        message = render_to_string('accounts/email_verification_email.html', {
            'user': user,
            'verification_link': verification_link,
        })

        send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
        # user_profile = Profile.objects.create(user=user,is_email_verified=False,user_type=user_type,email_token = token)
        user_profile = Profile.objects.create(user=user,user_type=user_type)
        user_profile.save()
        return render(request, 'accounts/verification_request.html')
    user_types = Profile.USER_TYPES
    return render(request, 'accounts/signup.html', {'user_types': user_types})


def verify_email_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()

        # user_Profile = Profile.objects.get(user=user)
        # user_Profile.is_email_verified = True
        # user_Profile.save()

        return render(request, 'accounts/verification_success.html')
    else:
        return render(request, 'accounts/verification_error.html')

from rest_framework_simplejwt.tokens import TokenUser

def login_view(request):
    if request.method == 'POST':
        print("\nlogin me hu\n", )
        email = request.POST.get('email')
        # username = request.POST.get('username')
        password = request.POST.get('password')
        form_user_type = request.POST.get('user_type')  # Get user type from form
        print(f"\nlogin view me print kiya hai {email} {password} {form_user_type}\n")

        if not User.objects.filter(email=email).exists():
               messages.error(request, "Invalid Email")
               return redirect('login')
        
        user = User.objects.get(email=email)
        username = user.username
        user_type = user.profile.user_type
        user = authenticate(request, username=username, password=password)
        print(user, f'user is None {user is None}')
        
        if user is not None and user_type == form_user_type:
            login(request, user)
            # return redirect('home')

            refresh = RefreshToken.for_user(user)
            token = str(refresh.access_token)

            # Additional context to return in response
            user_data = TokenUser(user).data  # Corrected usage here
            response_data = {
                'token': token,
                'user': user_data
            }
            return JsonResponse(response_data, status=status.HTTP_200_OK)
        else:
            print('else chala')
            print(f'user is not None {user is not None} user_type == form_user_type  {user_type} == {form_user_type} {user_type == form_user_type}')
            messages.error(request,'password or user_type is wrong')
            return redirect('login')
    user_types = Profile.USER_TYPES
    return render(request, 'accounts/login.html', {'user_types': user_types})

# def login_view(request):
#     if request.method == 'POST':
#         print("\nlogin me hu\n", )
#         email = request.POST.get('email')
#         # username = request.POST.get('username')
#         password = request.POST.get('password')
#         form_user_type = request.POST.get('user_type')  # Get user type from form
#         print(f"\nlogin view me print kiya hai {email} {password} {form_user_type}\n")

#         if not User.objects.filter(email=email).exists():
#                messages.error(request, "Invalid Email")
#                return redirect('login')
#         # Authenticate user based on username, password, and user type
#         # user = CustomUserBackend().authenticate(request, username=username, password=password, user_type=user_type)
        
#         user = User.objects.get(email=email)
#         # username = User.objects.get(email=email).username
#         username = user.username
#         user_type = user.profile.user_type
#         user = authenticate(request, username=username, password=password)
#         print(user, f'user is None {user is None}')
#         if user is not None and user_type == form_user_type:
#             login(request, user)
#             refresh = RefreshToken.for_user(user)
#             token = str(refresh.access_token)

#             # Additional context to return in response
#             user_data = JWTTokenUser(user).data
#             response_data = {
#                 'token': token,
#                 'user': user_data
#             }
#             return JsonResponse(response_data, status=status.HTTP_200_OK)
#             # print("\nredirecting to login\n")
#             # # context = {"message":f'you are user {username} with  {user_type} user type you will be having following access'}
#             # # print(context['message'])
#             # login(request, user)
#             # print("\ngoing to home\n")
#             # # return render(request,'accounts/home.html',context=context)
#             # return redirect('home')
#         else:
#             print('else chala')
#             print(f'user is not None {user is not None} user_type == form_user_type  {user_type} == {form_user_type} {user_type == form_user_type}')
#             messages.error(request,'password or user_type is wrong')
#             # print('message ke baad')
#             return redirect('login')
#     user_types = Profile.USER_TYPES
#     return render(request, 'accounts/login.html', {'user_types': user_types})

# Forgot Password View
class CustomPasswordResetView(PasswordResetView):
    template_name = 'accounts/forgot_password.html'

# Reset Password View
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'accounts/reset_password.html'

def forgot_password_view(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        print("yahi forgot function hai")
        if form.is_valid():
            # here we can also add another logic for password reset
            pass
    else:
        form = ForgotPasswordForm()
    return render(request, 'accounts/forgot_password.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')
