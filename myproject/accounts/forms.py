from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User

class SignupForm(UserCreationForm):
    email = forms.EmailField(max_length=200, help_text='Required')

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')



class LoginForm(AuthenticationForm):
    class Meta:
        model = User
        fields = ('username', 'password')




class ForgotPasswordForm(PasswordResetForm):
    email = forms.EmailField(max_length=254)
