from django.shortcuts import render, redirect, HttpResponse
import uuid
from django.http import HttpResponseRedirect
import jwt
from django.views.decorators.csrf import csrf_exempt
import requests
from .models import Employee
from time import sleep
service_mapping = {"service1.local":"http://192.168.0.153:8001","service2.local":"http://192.168.0.153:9001"}

HttpResponseRedirect.allowed_schemes.append('ztna')

key = 'secret'
threshold = 0.5 

#list of authenticated users.
authenticatedUsers=[]

def badPosturePage(request):
	return render(request,'app/badP.html')

def logHimOut(request,uid):
	authenticatedUsers.remove(uid.split(';')[0])
	
	print("Logged out user:",uid)
	print("Users Active: ",authenticatedUsers)
	res = requests.post("http://192.168.0.153:8001/logoutUser/"+uid)
	res1 = requests.post("http://192.168.0.153:8002/logoutUser/"+uid)
	
	return HttpResponseRedirect("http://192.168.0.153:8000/accounts/logout/")

#todo wait for a few seconds for user to send init posture after timeout return to dash with
def pollReq(request,uid):
	
	if(uid in authenticatedUsers):
		return HttpResponseRedirect("http://192.168.0.153:8001/dash/%s" % uid)
	else:
		return HttpResponseRedirect('http://192.168.0.153:8000/bad_postures/')

def homepage(request):
	return render(request,'app/sso_home.html')

@csrf_exempt
def agent_invoke(request):
	#sleep(5)
	#return HttpResponseRedirect('http://localhost:8001/')
	username = None
	if request.user.is_authenticated:
		username = request.user.username
		modelResult = Employee.objects.filter(username=username)
		#print(modelResult[0].uid)
		uid = modelResult[0].uid#uuid.uuid4().__str__()
		
		link = "ztna://service1?uuid=" + uid + "&username=" + username
		print(link)
		#print(request.body)
		#render(request,'app/success.html')
		print("_________")
		#print(redirect(link))
		#return redirect(link)
		return render(request,'app/success.html',{"link":link,"uid":uid})
	
	else:
		return HttpResponseRedirect('http://192.168.0.153:8000/')

@csrf_exempt
def authenticateToken(request): #responses head to posture checker.

	header_dict = dict(request.headers.items())

	token = header_dict.get("Authorization")

	try:
		
		token = jwt.decode(token,key, algorithm='HS256')
		print(token)
		
		revoked = bool(token.get('revoked'))
		
		if not revoked:

			authenticatedUsers.append(token["uuid"])

			print("User ",token["uuid"]," Authenticated.")
			print("Users Active:",authenticatedUsers)
			
			return HttpResponse('YES')
		
		else:

			return HttpResponse('NO')

	except Exception as e:
		print(e)
		return HttpResponse("You are not authorized!")
@csrf_exempt
def user_state(request,uuid):
	if uuid in authenticatedUsers:
		return HttpResponse('active')
	else:
		return HttpResponse('inactive')

