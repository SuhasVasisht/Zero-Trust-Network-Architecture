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
    #role
    role = models.ForeignKey('Role',on_delete=DO_NOTHING)

    def __str__(self):
        return self.name


class Role(models.Model):
	#role in org
	role = models.CharField(primary_key=True,max_length=200)
	
	#resources the user has access to
	aceAdminDashboard = models.BooleanField(default=False)
	codebase = models.BooleanField(default=False)
	customerDatabase = models.BooleanField(default=False)
	financialRecords = models.BooleanField(default=False)
	employeeRecords = models.BooleanField(default=False)
	def __str__(self):
		return self.role