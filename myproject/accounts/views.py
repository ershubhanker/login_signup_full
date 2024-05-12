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
from .models import CustomUser 
from django.contrib import messages

@login_required(login_url='login')
def home_page(request):
    user_type = request.user.user_type
    user_name = request.user
    if user_type == 'employee':
        print("ye emplouyee hai is isme jaane ike paermssion nahi hai")
        # Logic for employee user type
    #     pass
    elif user_type == 'hr':
        print("tum hr hop yaha aa skati ho par tum admin ke neech ho")
    #     # Logic for HR user type
    #     pass
    elif user_type == 'custom_admin':
        print("tu admin hai full access")
        # Logic for custom admin user type
    #     pass
    else:
        print("redirectinh to other page")
    #     # Handle unknown user types
    #     pass
    # context = {"message":f'you are {user_type} user type you will be having following access in home page'}
    context = {'message':f'you are user {user_name} of user_type {user_type}'}
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
            print(f"while verify mail request the token is {token}")
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
        
        user = CustomUser.objects.filter(username=username)
        
        if user.exists():
            messages.error(request, "username already exist.")
            return redirect('signup')
        
        if password1!=password2:
            messages.error(request, "password dosent matches")
            return redirect('signup')
        
        user = CustomUser.objects.create(
               username=username,
               email=email,
               user_type = user_type
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

        return render(request, 'accounts/verification_request.html')
    user_types = CustomUser.USER_TYPES
    return render(request, 'accounts/signup.html', {'user_types': user_types})

def verify_email_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    print(token,user)
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'accounts/verification_success.html')
    else:
        print(f'(user is not none {user is not None} )',f'tokens matched {default_token_generator.check_token(user, token)}')
        return render(request, 'accounts/verification_error.html')


from django.contrib.auth import authenticate, login
from .forms import LoginForm
from .backends import CustomUserBackend

def login_view(request):
    if request.method == 'POST':
        print("\nlogin me hu\n", )
        email = request.POST.get('email')
        password = request.POST.get('password')
        user_type = request.POST.get('user_type')  # Get user type from form
        print(f"\nlogin view me print kiya hai {email} {password} {user_type}\n")

        if not CustomUser.objects.filter(email=email).exists():
               messages.error(request, "Invalid username")
               return redirect('login')
        # Authenticate user based on username, password, and user type
        # user = CustomUserBackend().authenticate(request, username=username, password=password, user_type=user_type)
        user = CustomUserBackend().authenticate(request, email=email, password=password, user_type=user_type)
        print(user, f'user is None {user is None}')
        if user is not None:
            print("\nredirecting to login\n")
            # context = {"message":f'you are user {username} with  {user_type} user type you will be having following access'}
            # print(context['message'])
            login(request, user)
            print("\ngoing to home\n")
            # return render(request,'accounts/home.html',context=context)
            return redirect('home')
        else:
            print('else chala')
            messages.error(request,'password or usertype is wrong')
            # print('message ke baad')
            return redirect('login')
    user_types = CustomUser.USER_TYPES
    return render(request, 'accounts/login.html', {'user_types': user_types})


def forgot_password_view(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        print(f'form.is_valid() value is {form.is_valid()}')
        if form.is_valid():
            email = form.cleaned_data.get('email')
            user = CustomUser.objects.get(email = email)
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
            pass
    else:
        form = ForgotPasswordForm()
    return render(request, 'accounts/forgot_password.html', {'form': form})



from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView

# Forgot Password View
class CustomPasswordResetView(PasswordResetView):
    template_name = 'accounts/forgot_password.html'

# Reset Password View
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'accounts/reset_password.html'


# class CustomPasswordResetView(PasswordResetView):
#     template_name = 'accounts/password_reset_form.html'  # Customize template if needed
#     email_template_name = 'accounts/password_reset_email.html'  # Customize email template if needed
#     success_url = '/password_reset/done/'  # Customize success URL if needed

#     def form_valid(self, form):
#         # Your form validation logic here
#         # Get the user object and other necessary data
#         user = form.get_user()
#         protocol = 'https' if self.request.is_secure() else 'http'
#         domain = self.request.get_host()
#         site_name = 'YourSiteName'  # Replace with your site name
        

#         # Pass the necessary data to the template context
#         context = {
#             'user': user,
#             'protocol': protocol,
#             'domain': domain,
#             'site_name': site_name,
#         }

#         # Pass the context to the email template renderer
#         self.send_mail(
#             self.email_template_name,
#             context,
#             **{
#                 'email': user.email,
#                 'subject': 'Password Reset',  # Customize email subject if needed
#             }
#         )

#         return super().form_valid(form)

def logout_view(request):
    logout(request)
    return redirect('login')
