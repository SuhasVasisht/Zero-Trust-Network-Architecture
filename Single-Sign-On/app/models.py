from django.db import models
from django.conf import settings
from django.db.models.base import Model
from django.db.models.deletion import DO_NOTHING

class Employee(models.Model):
    name = models.CharField(max_length=200)

    #username
    username = models.CharField(max_length=200)
    #uid
    uid = models.CharField(primary_key=True,max_length=200)

    def __str__(self):
        return self.name