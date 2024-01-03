from django.db import models

# Create your models here.
class CustomUser(models.Model):
    username = models.CharField(max_length=50,null=True,blank=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=50, null=True, blank=True)
