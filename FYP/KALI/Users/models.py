from django.db import models
from django.contrib.auth import get_user_model

# Create your models here.
class User(models.Model):
    username = models.CharField(max_length=255 , unique=True)
    password = models.CharField(max_length=255)
    
    def __str__(self):
        return self.username



User = get_user_model()


class PhoneDetail(models.Model):
    number = models.CharField(max_length=15)
    name = models.CharField(max_length=255)
    father_name = models.CharField(max_length=255)
    cnic = models.CharField(max_length=15)
    address = models.TextField()

    def __str__(self):
        return f"{self.name} ({self.number})"