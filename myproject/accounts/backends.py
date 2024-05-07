from django.contrib.auth.backends import ModelBackend
from .models import CustomUser

# accounts/backends.py

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

# class CustomUserBackend(BaseBackend):
#     def authenticate(self, request, username=None, password=None, user_type=None, **kwargs):
#         print("\n\nin auth\n\n")
#         UserModel = get_user_model()
#         try:
#             user = UserModel.objects.get(username=username)
#             print(f'user = {user} password matches {user.check_password(password)} type also matches {user.user_type == user_type}')
#             if user.check_password(password) and user.user_type == user_type:
#                 return user
#         except UserModel.DoesNotExist:
#             print("does not exist")
#             return None

# class CustomUserBackend(ModelBackend):
#     def authenticate(self, request, username=None, password=None, **kwargs):
#         try:
#             user = CustomUser.objects.get(username=username)
#             print(f'user = {user} password matches {user.check_password(password)} type also user type is {user.user_type }')
            
#             if user.check_password(password) and user.user_type == kwargs['user_type']:
#                 return user
#         except CustomUser.DoesNotExist:
#             print("does not exist")
#             return None

class CustomUserBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(username=username)
            # print(f'''\n\nuser = {user} password matches {user.check_password(password)} type also user type is {user.user_type} and last request.POST.get('user_type') {request.POST.get('user_type')} kwargs  {kwargs['user_type']}\n\n ''')
            print(f'''\n\nuser = {user} password matches {user.check_password(password)} type also user type is {user.user_type} and last request.POST.get('user_type') {request.POST.get('user_type')} ''')
            
            if user.check_password(password) and user.user_type == request.POST.get('user_type'):
                print('\n\nuser is returned through auth\n\n')
                return user
        except CustomUser.DoesNotExist:
            print("does not exist error in try auth\n\n")
            return None