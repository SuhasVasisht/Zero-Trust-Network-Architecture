from django.db import models
from django.conf import settings
from django.db.models.base import Model
from django.db.models.deletion import DO_NOTHING

class Employee(models.Model):
	name = models.CharField(max_length=200)
	
	#username
	username = models.CharField(primary_key=True,max_length=200)

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
#Test 1: Startup Applications
class Test0_Startup_Items(models.Model):
	
	author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	
	applicationName = models.CharField(max_length=200)
	
	def __str__(self):
		return self.applicationName

#Test 1: Network Applications
class Test1_Network_Applications(models.Model):
	
	#author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	
	applicationName = models.CharField(max_length=200)
	
	flagged = models.BooleanField(default=False)

	def __str__(self):
		return self.applicationName

#Test 2: Browser Extensions
class Test2_Flagged_Browser_Extensions(models.Model):
	
	#author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	
	extensionName = models.CharField(max_length=200)
	
	def __str__(self):
		return self.extensionName

#Test 3: win sec center
class Test3_Win_Sec_Center_Bad_States(models.Model):
	
	author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	
	stateName = models.CharField(max_length=200)
	def __str__(self):
		return self.stateName

#Test 7: hotfix
class Test7_Windows_Hotfixes(models.Model):
	
	author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	
	hotfixName = models.CharField(max_length=200)
	
	def __str__(self):
		return self.hotfixName

#Test 6: hotfix
class Test6_OS_Versions(models.Model):
	
	author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	
	OSName = models.CharField(max_length=200)
	OSVersion = models.CharField(max_length=200)
	def __str__(self):
		return self.OSName+":"+self.OSVersion