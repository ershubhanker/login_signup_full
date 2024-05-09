# Create your models here.
# accounts/models.py
from typing import Any
from django.contrib.auth.models import AbstractUser
from django.db import models

# class CustomUser(AbstractUser):
#     USER_TYPES = [
#         ('employee', 'Employee'),
#         ('hr', 'HR'),
#         ('custom_admin', 'Custom Admin'),
#     ]
#     user_type = models.CharField(max_length=20, choices=USER_TYPES)

#     def __str__(self):
#         return self.username


from django.contrib.auth.models import AbstractUser, Group, Permission

from django.utils.translation import gettext as _

class CustomUser(AbstractUser):
    USER_TYPES = [
        ('employee', 'Employee'),
        ('hr', 'HR'),
        ('custom_admin', 'Custom Admin'),
    ]
    user_type = models.CharField(max_length=20, choices=USER_TYPES)
    
    # Add custom related names to avoid clashes with default User model
    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        related_name='custom_user_set',
        related_query_name='custom_user',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        related_name='custom_user_set',
        related_query_name='custom_user',
        help_text=_('Specific permissions for this user.'),
    )

    def __str__(self):
        return self.username 
    
    def __getattribute__(self, name: str) -> Any:
        return super().__getattribute__(name)
    



