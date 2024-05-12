from django.contrib.auth.backends import ModelBackend
from .models import CustomUser

# accounts/backends.py

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model



class CustomUserBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(email=email)
            # print(f'''\n\nuser = {user} password matches {user.check_password(password)} type also user type is {user.user_type} and last request.POST.get('user_type') {request.POST.get('user_type')} kwargs  {kwargs['user_type']}\n\n ''')
            # print(f'''\n\nuser = {user} password matches {user.check_password(password)} type also user type is {user.user_type} and last request.POST.get('user_type') {request.POST.get('user_type')} ''')
            print(f'''\n\n user.user type is {user.user_type} and request.POST.get('user_type') {request.POST.get('user_type')}, condition = {str(user.user_type) == str(request.POST.get('user_type'))} ''')
            
            if user.check_password(password) and user.user_type == request.POST.get('user_type'):
                print('\n\nuser is returned through custom auth\n\n')
                return user
            else:
                print('user type dosent matches')
                return None
        except CustomUser.DoesNotExist:
            print("does not exist error in try auth\n\n")
            return None