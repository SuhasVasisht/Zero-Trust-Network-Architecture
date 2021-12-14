from django.shortcuts import render,redirect
from django.http import HttpResponse
import uuid
from django.http import HttpResponseRedirect
from .forms import UserRegisterForm
from django.contrib import messages
from django.shortcuts import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Employee,Role
import requests
resourceMap = {
					"aceAdminDashboard":"http://192.168.0.153:9001/admin",
					"codebase":"http://192.168.0.153:8002/codebase",
					"customerDatabase":"http://192.168.0.153:8002/customerDatabase",
					"financialRecords":"http://192.168.0.153:8002/financialRecords",
					"employeeRecords":"http://192.168.0.153:8002/employeeRecords"
				}

#added here
states = {
	'A' : '',
	'B' : 'V',
	'C' : 'VC',
	'D' : 'VCM',
	'E' : 'VCMDd',
}

authenticatedUsers= {}
badUsers = []

@csrf_exempt
def logUserOut(request,uid):
	print("logging ",uid," out")
	authenticatedUsers.pop(uid)
	print(authenticatedUsers)
	return HttpResponse("OK")

def requestResolver(request,req):
	print(req)
	uid = req.split("&")[0]
	resourceRequested = req.split("&")[1]

	if uid not in authenticatedUsers.keys():
		return HttpResponseRedirect('http://192.168.0.153:8001/badP/')	

	#resolve request to resource here. (Proxy Part)
	link = resourceMap[resourceRequested]
	permissions = authenticatedUsers[uid]
	#check which state the user is in ie. State A or B or C etc idk how to enforce this . so far we work in a binary way access or no access. 
	res = requests.post("http://192.168.0.153:8002/updateperm/",headers={'uid':uid,'perm':permissions},data={'ok':1})
	return HttpResponseRedirect(link+'/'+uid)

def badP(request):
	return render(request,'service/badP.html')

@csrf_exempt
def cutOffUser(request):
	header_dict = dict(request.headers.items())
	#print(header_dict)
	badUid = header_dict.get("Uid")
	try:
		
		print("Bad Postures from UID:",badUid)
		print("cutting off access to UID:",badUid)

		authenticatedUsers.pop(badUid)
		badUsers.append(badUid)
		#propagate to resources
		res = requests.post("http://192.168.0.153:8002/cutOff/",headers={'uid':badUid},data={'ok':1})
		return HttpResponse('CutOff'+badUid)

	except Exception as e:
		print(e)
		return HttpResponse("Error occured while cutting off user")
	


@csrf_exempt
def updatePerm(request):
	header_dict = dict(request.headers.items())
	#print(header_dict)
	Uid = header_dict.get("Uid")
	permission = header_dict.get("Perm")
	try:
		authenticatedUsers[Uid] = states[permission]
		#print(authenticatedUsers)
		res = requests.post("http://192.168.0.153:8002/updateperm/",headers={'uid':Uid,'perm':states[permission]},data={'ok':1})
		return HttpResponse('User permission of ' + Uid + ' is effectively '+permission)
		
	except Exception as e:
		print(e)
		return HttpResponse("Error occured while updating permissions")

def home(request):
    return HttpResponse('Hello, World!')

'''
@csrf_exempt
def register(request):
	if request.method == 'POST':
		header_dict = dict(request.headers.items())
		if "Authorization" not in header_dict.keys():
			return HttpResponseRedirect("http://192.168.0.153:8000/submit/{}/".format(request.POST.get("username")))
		messages.success(request, f'Your account has been created! You are now able to log in')
		
		return HttpResponse("Logged In")
	else:
		print("Im a GET")
		#print(request.body)
		form = UserRegisterForm()
	return render(request, 'service/index.html', {'form': form})
'''
@csrf_exempt
def status(request):
	print(request.body)
	return render(request, 'service/status.html',{})

def revoked(request):
    return HttpResponse("You are not authorized!")

def dashboard(request,uid):
	
	if uid not in badUsers and uid not in authenticatedUsers.keys():
		print("Added user")

		#adding the user to the dict with the uid as key and an empty list as the value
		authenticatedUsers[uid]=''
		
	modelResult = Employee.objects.filter(uid=uid)
	userRole = modelResult[0].role
	username = modelResult[0].username
	resourcesResult = Role.objects.filter(role=userRole)
	
	resourceLinks=[]
	
	
	if(resourcesResult[0].aceAdminDashboard):
		resourceLinks.append("aceAdminDashboard")
	if(resourcesResult[0].codebase):
		resourceLinks.append("codebase")
	if(resourcesResult[0].customerDatabase):
		resourceLinks.append("customerDatabase")
	if(resourcesResult[0].financialRecords):
		resourceLinks.append("financialRecords")
	if(resourcesResult[0].employeeRecords):
		resourceLinks.append("employeeRecords")

	print("entered dashboard:","uid: ",uid," Role: ",userRole)

	return render(request,'service/dashboard.html',{"uid":uid,"resourceLinks":resourceLinks,"username":username})