from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser
# from django.contrib.auth.models import User



  # Add this line

class SignupForm(UserCreationForm):
    email = forms.EmailField(max_length=200, help_text='Required')
    user_type = forms.ChoiceField(choices=CustomUser.USER_TYPES)

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1', 'password2', 'user_type')

class LoginForm(AuthenticationForm):
    user_type = forms.ChoiceField(choices=CustomUser.USER_TYPES)

    class Meta:
        model = CustomUser
        fields = ('username', 'password', 'user_type')


class ForgotPasswordForm(PasswordResetForm):
    email = forms.EmailField(max_length=254)

    # class Meta:
    #     model = CustomUser

    def clean_email(self):
        email = self.cleaned_data['email']
        if not CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("This email address is not associated with any account.")
        return email

        
