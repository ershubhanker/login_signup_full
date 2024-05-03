# # Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .forms import SignupForm, LoginForm, ForgotPasswordForm
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

@login_required(login_url='login')
def home_page(request):
    return render(request,'accounts/home.html')


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
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # User is inactive until email is verified
            user.save()

            # Send verification email
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
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

            return render(request, 'accounts/verification_request.html')
    else:
        form = SignupForm()
    return render(request, 'accounts/signup.html', {'form': form})

def verify_email_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'accounts/verification_success.html')
    else:
        return render(request, 'accounts/verification_error.html')


def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                context = {'username':username}
                login(request, user)
                return render(request,'accounts/home.html',context=context)
    else:
        form = LoginForm()
    return render(request, 'accounts/login.html', {'form': form})

def forgot_password_view(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            # here we can also add another logic for password reset
            pass
    else:
        form = ForgotPasswordForm()
    return render(request, 'accounts/forgot_password.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')
