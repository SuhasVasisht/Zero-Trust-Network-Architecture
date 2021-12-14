from django.http.response import HttpResponseRedirect
from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
#from bs4 import BeautifulSoup
import json 
import jwt 
import requests
import time
from tabulate import tabulate

from .device_tests.h_tests import *
from .device_tests.c_tests import *

#from .posture_tests.test_file import *


parameter_names=[]


#user states:  MAYBE NOT NEEDED HERE
states = {
	'A' : [],
	'B' : ['View'],
	'C' : ['View', 'Create'],
	'D' : ['View', 'Create', 'Modify'],
	'E' : ['View', 'Create', 'Modify', 'Delete', 'Download']
}

prev_state = ''
state_count = -1

old_score=0

#-------------------------------------------------------------------------------------------------------#
#											Trust Score Functions										#
#-------------------------------------------------------------------------------------------------------#

def initial_trust_score(posture_indices, postures):
	initial = 0.5
	change = trust_calc(posture_indices, postures)
	trust_score = initial + change

	if trust_score < 0 :
		trust_score = 0
	if trust_score > 1 :
		trust_score = 1

	return trust_score


def trust_calc(postures_indices, postures):
	change = 0
	trustVals = []
	issueList = []

	parameter_names = postures["parameters"]
	parameter_descs = postures["parameter_descriptions"]
	parameter_descriptions=[]
	

	for test_parameter in parameter_names:
		
		parameter_descriptions.append(parameter_descs[test_parameter]) 

		if test_parameter in C_TEST_Dispatcher.keys():
			change0, issue0 = C_TEST_Dispatcher[test_parameter](postures[test_parameter])
			issueList.append(issue0)
			trustVals.append(change0)
			change+=change0
		
		if test_parameter in H_TEST_Dispatcher.keys():
			change1, issue1 = H_TEST_Dispatcher[test_parameter](postures[test_parameter])
			issueList.append(issue1)
			trustVals.append(change1)
			change+=change1

	#printing score for each parameter
	headers = ['Test No.', 'Description', 'Score', "Status"]

	table = zip(parameter_names, parameter_descriptions,trustVals, issueList)
	print(tabulate(table, headers=headers))


	return change

def determine_state(trust_score):
	if trust_score < 0.2:
		return 'A'
	if trust_score >=0.2 and trust_score < 0.4:
		return 'B'
	if trust_score >=0.4 and trust_score < 0.6:
		return 'C'
	if trust_score >=0.6 and trust_score < 0.8:
		return 'D'
	if trust_score >=0.8:
		return 'E'
	
def determine_permissions(state):
	global prev_state
	global state_count
	current_perms = state
	if state == 'C' and prev_state > 'C':
		state_count += 1
		if state_count < 2:
			return 'B'
	
	if state == 'D' and prev_state > 'D':
		state_count += 1
		if state_count < 2:
			return 'C'

	prev_state = state
	state_count = -1
	return current_perms

def initial_check(payload):
	device_postures = payload
	uuid = payload["temp_uuid"]
	posture_indices = [i for i in range(len(device_postures))]
	trust_score = initial_trust_score(posture_indices, device_postures)#float(payload['score'])
	state = determine_state(trust_score)
	permissions = determine_permissions(state)
	print("PERMISSIONS = ", permissions)
	res = requests.post("http://192.168.0.153:8001/updateperm/",headers={'uid':uuid,'perm':permissions},data={'ok':1})
	
	print(res.text)
	if trust_score <= 0.2:
		revoked=True
	else:
		revoked=False
	print("\n\nTrust Score = ",trust_score)
	return revoked , permissions

#-------------------------------------------------------------------------------------------------------#
#											Test Functions												#
#-------------------------------------------------------------------------------------------------------#

def test_posture_check(payload):
	device_postures = payload
	uuid = payload["temp_uuid"]
	posture_indices = [i for i in range(len(device_postures))]
	trust_score = initial_trust_score(posture_indices, device_postures)#float(payload['score'])
	state = determine_state(trust_score)
	permissions = determine_permissions(state)
	print("PERMISSIONS = ", permissions)
	
	if trust_score <= 0.2:
		revoked=True
	else:
		revoked=False
	print("\n\nTrust Score = ",trust_score)

	return revoked , permissions

@csrf_exempt
def test_posture(request):
	#initalize payload dict
	payload = dict()

	if request.method == "POST":
		print("\nReceived Test Posture set.")
		#extracting payload
		#Note the payload key values have to match those set in the table_names list in agentreal.py
		payload = json.loads(request.body)
		#print(payload.keys())
		uuid = payload["temp_uuid"]
		username = payload["username"]
		revoked, score = test_posture_check(payload)
		print("Revoked:",revoked)
		if(revoked==True):
			#res = requests.post("http://192.168.0.153:8001/cutOff/",headers={'uid':uuid},data={'ok':1})
			return HttpResponse("bad set received.")
		return HttpResponse("OK")

	return HttpResponse("Error! Get Req not allowed!!")

#--------------------------------------------------------------------------------------------------------

# JWT Secret 
key = 'secret'

prev_good_posture = []

blacklisted_AddOns = []

prev_payload_timestamp={}
TimeBetweenPayloads = 5

@csrf_exempt
def scheduledPayload(request):
	payload = dict()
	
	if request.method == "POST":

		payload = json.loads(request.body)

		uuid = payload["temp_uuid"]
		username = payload["username"]
		
		global parameter_names
		parameter_names = payload["parameters"]
		
		elapsedTime=0
		
		if uuid not in prev_payload_timestamp.keys():
			prev_payload_timestamp[uuid]=time.time()
		else:
			elapsedTime=time.time()-prev_payload_timestamp[uuid]
			prev_payload_timestamp[uuid]=time.time()
			print("\nTime Between Payloads: ",elapsedTime)
			
		#use elapsedTime along with a concesion for time spent in traffic#
		#log out/ cut off if response takes too long. potential for something to have gone wrong.
		

		print("Scheduled Payload Sent By:",uuid)
		#global old_score
		revoked, permissions = initial_check(payload)
		
		#old_score=score

		usr_state = requests.post("http://192.168.0.153:8000/poll_usr_state/{}".format(uuid))

		if revoked == False and usr_state.text== 'active':
			print("posture good")
			return HttpResponse("YES")
		
		if usr_state.text!= 'active':
			print("user has logged out")
			print("Terminating Scheduled-Payload Contract for User: ",uuid)
			return HttpResponse("NO")
		
		print("\nUser has logged out or has presented bad postures.")
		print("Terminating Scheduled-Payload Contract for User: ",uuid)

		res = requests.post("http://192.168.0.153:8001/cutOff/",headers={'uid':uuid},data={'ok':1})
		return HttpResponse("NO")

	else:
		return HttpResponse("GET not allowed!")

@csrf_exempt
def sso_login(request):
	'''
	global scraperFlag
	if(scraperFlag==False):
		scraperFunc()
		
		scraperFlag=True
	'''
	#initalize payload dict
	payload = dict()

	if request.method == "POST":
		print("\nReceived Init Postures.")
		#extracting payload
		#Note the payload key values have to match those set in the table_names list in agentreal.py
		payload = json.loads(request.body)
		f=open("utsav-posture.json","w")
		f.write(str(request.body))
		f.close()
		#print(payload.keys())
		uuid = payload["temp_uuid"]
		username = payload["username"]

		global parameter_names
		parameter_names = payload["parameters"]
		print(parameter_names)
		revoked, score = initial_check(payload)
		global old_score
		old_score=score
		
		raw_token = {"uuid" : uuid, "revoked":revoked}
		
		token = jwt.encode(raw_token, key, algorithm='HS256').decode()

		r = requests.post("http://192.168.0.153:8000/authenticateToken/",headers={'Authorization':token},data={'ok':1})
		
		if r.text == 'YES':
			print("Granted Access To Dash.")
			print("\nInitiating Scheduled-Payload Contract...")
			repl='YES:{}'.format(TimeBetweenPayloads)
		else:
			print("Denied Access To Dash.")
			repl='NO:0'
		return HttpResponse(repl)

	else:
		return HttpResponse("GET not allowed!")


'''
scraperFlag=False

def scraperFunc():
	URL = "https://owasp.org/www-project-vulnerable-web-applications-directory/"
	r = requests.get(URL)
	
	soup = BeautifulSoup(r.content, 'html.parser')
	table = soup.find('section', attrs = {'id':'sec-offline'})
	offTable = list(table.children)[5]


	badApps = []
	filterWords = ["Download", "Downloads", "Guide", "Docker"]

	result = offTable.find_all('a')
	for row in result:
		app = row.text
		if app not in filterWords and '[' not in app:
			badApps.append(app)

	for e in badApps:
		instance = Test1_Network_Applications.objects.update_or_create(applicationName=e,flagged=True)

	badExtenstions = []
	headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36"}
	extURL = "https://www.makeuseof.com/tag/unsafe-firefox-extensions/"
	extr = requests.get(extURL,headers=headers)
	extSoup = BeautifulSoup(extr.content, 'html.parser')
	extTable = extSoup.find('article', attrs = {'class':'w-article article'})
	extResult = extTable.find_all('h2')
	for row in extResult:
		extension = row.text
		if "Beware" not in extension:
			badExtenstions.append(extension.strip()[3:])
	
	for element in badExtenstions:
		instance=Test2_Flagged_Browser_Extensions.objects.update_or_create(extensionName=element)

#home page
def test_page(request):
	return render(request,"dashboard/hi.html")
'''