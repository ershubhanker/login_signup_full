from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    USER_TYPES = [
        ('employee', 'Employee'),
        ('hr', 'HR')
        # ('custom_admin', 'Custom Admin'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    user_type = models.CharField(max_length=20, choices=USER_TYPES)
    # is_email_verified = models.BooleanField(default=False)
    # email_token = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f'{self.user.username}'

