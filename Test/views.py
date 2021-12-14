from django.http.response import HttpResponseRedirect
from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import json 
from pymongo import MongoClient
from deepdiff import DeepDiff 
import jwt 
import requests
import datetime
import time

from .models import Test0_Startup_Items,Test1_Network_Applications,Test2_Flagged_Browser_Extensions,Test3_Win_Sec_Center_Bad_States, Test6_OS_Versions,Test7_Windows_Hotfixes

parameter_names=[
    "Startup_Items", # 0 Startup Items
    "Network_Apps", # 1 Network Applications
    "Browser_Extensions", # 2 Browser Extensions
    "Win_Sec_Center", # 3 win sec cen
    "Sec_Products", # 4 win sec products
    "Prog_WO_Binaries",# 5 Programs without binaries
    "OS_Version",# 6 OS ver
    "Hotfixes",# 7 hotfix
    "Priv_Users", # 8 privledged users
    "CCleaner",
    "AmmyyAdmin",
    "Advanced_IPScanner",
]

#threat levels
threat={
	"H":-1000,
	"M":-0.1,
	"OK":0.02
}
old_score=0
#--------------------------------------------------------------------------------------------------------
#								Analysis Functions
#--------------------------------------------------------------------------------------------------------


def analyse_Startup_Items(Startup_Items):

	#items defined by org.
	#defined_items=["SecurityHealth","desktop.ini"]
	modelResult = Test0_Startup_Items.objects.all()
	
	defined_items=[]

	for e in modelResult:
		defined_items.append(e.applicationName)

	count=0

	for e in Startup_Items['name']:
		if e not in defined_items:
			count+=1

	if count > 0:
		return threat["M"]*count

	return threat["OK"]

def analyse_Network_Apps(Network_Apps):

	defined_apps=["svchost.exe","chrome.exe","SearchApp.exe","OneDrive.exe","WinStore.App.exe","Code.exe"]
	
	#flagged_apps=["python3.9.exe","powershell.exe","cmd.exe","python.exe"]
	
	flagged_apps=[]

	modelResult = Test1_Network_Applications.objects.filter(flagged=True)
	
	for e in modelResult:
		flagged_apps.append(e.applicationName)


	count=0
	for e in Network_Apps["name"]:
		if e not in defined_apps:
			i = Network_Apps["name"].index(e)
			if(Network_Apps["remote_address"][i] !="192.168.0.153" and e in flagged_apps):
				return threat["H"]
	
	return threat["OK"]

def analyse_Browser_Extensions(Browser_Extensions):

	flagged_extensions=["Hola","FindMeFreebies","Hover Zoom","AVG Online Security","EasyToolOnline Promos","LoveTestPro Ad Offers","The Pirate Bay Torrent Search","The Pirate Bay torrent Search"]

	count = 0
	for e in Browser_Extensions['name']:
		if e in flagged_extensions:
			count+=1
	
	if count>0:
		return count*threat["M"]

	return threat["OK"]

def analyse_Win_Sec_Center(Win_Sec_Center):

	#badset=["Poor","Not Monitored","Error","Snoozed"]
	modelResult = Test3_Win_Sec_Center_Bad_States.objects.all()
	
	badset=[]

	for e in modelResult:
		badset.append(e.stateName)

	if Win_Sec_Center['firewall'] in badset:
		return threat["H"]

	if Win_Sec_Center['antivirus'] in badset:
		return threat["M"]

	if Win_Sec_Center['internet_settings'] in badset:
		return threat["H"]

	if Win_Sec_Center['antispyware'] in badset:
		return threat["H"]
	
	count = 0 
	if Win_Sec_Center['user_account_control'] in badset:
		count+=1
	
	if Win_Sec_Center['autoupdate'] in badset:
		count+=1
	
	if count>0:
		return count*threat["M"]

	return threat["OK"]

def analyse_Sec_Products(Sec_Products):

	if "Firewall" not in Sec_Products['type']:
		return threat["H"]
	
	if "Antivirus" not in Sec_Products['type']:
		return threat["H"]

	return threat["OK"]

def analyse_Prog_WO_Binaries(Prog_WO_Binaries):
	
	if len(Prog_WO_Binaries['name'])>0:
		return threat["H"]

	return threat["OK"]

#For now everything is ok.
def analyse_OS_Version(OS_Version):
	#connect model to this, it has a list of acceptable os versions
	return threat["OK"]

def analyse_Hotfixes(Hotfixes):
	#connect model to this, model has a list of hotfixes
	diff=5-len(Hotfixes['hotfix_id'])
	
	if diff >0:
		return diff*threat["M"]
	
	return threat["OK"]

def analyse_Priv_Users(Priv_Users):
	defined=["Administrator","ztnac"]
	
	for e in Priv_Users['username']:
		if e not in defined:
			return threat["H"]
	
	return threat["OK"]

def analyse_CCleaner(CCleaner):
	return threat["OK"]

def analyse_AmmyyAdmin(AmmyyAdmin):
	return threat["OK"]

def analyse_Advanced_IPScanner(Advanced_IPScanner):
	return threat["OK"]

#--------------------------------------------------------------------------------------------------------
old_parameters = [] #check if global works




#--------------------------------------------------------------------------------------------------------
#								Trust Score Functions
#--------------------------------------------------------------------------------------------------------

def initial_trust_score(posture_indices, postures):
	initial = 0.5
	change = trust_calc(posture_indices, postures)
	trust_score = initial + change

	if trust_score < 0 :
		trust_score = 0
	if trust_score > 1 :
		trust_score = 1

	return trust_score

def trust_calc(changed_postures_indices, changed_postures):
	change = 0
	if 0 in changed_postures_indices:
		change0 = analyse_Startup_Items(changed_postures[parameter_names[0]])
		print("0-----",change0)
		change+=change0

	if 1 in changed_postures_indices:
		change1= analyse_Network_Apps(changed_postures[parameter_names[1]])
		print("1-----",change1)
		change+=change1
	if 2 in changed_postures_indices:
		change2= analyse_Browser_Extensions(changed_postures[parameter_names[2]])
		print("2-----",change2)
		change+=change2
	if 3 in changed_postures_indices:
		change3= analyse_Win_Sec_Center(changed_postures[parameter_names[3]])
		print("3-----",change3)
		change+=change3
	if 4 in changed_postures_indices:
		change4= analyse_Sec_Products(changed_postures[parameter_names[4]])
		print("4-----",change4)
		change+=change4
	if 5 in changed_postures_indices:
		change5 = analyse_Prog_WO_Binaries(changed_postures[parameter_names[5]])
		print("5-----",change5)
		change+=change5
	if 6 in changed_postures_indices:
		change6 = analyse_OS_Version(changed_postures[parameter_names[6]])
		print("6-----",change6)
		change+=change6
	if 7 in changed_postures_indices:
		change7= analyse_Hotfixes(changed_postures[parameter_names[7]])
		print("7-----",change7)
		change+=change7
	if 8 in changed_postures_indices:
		change8 = analyse_Priv_Users(changed_postures[parameter_names[8]])
		print("8-----",change8)
		change+=change8
	if 9 in changed_postures_indices:
		change9= analyse_CCleaner(changed_postures[parameter_names[9]])
		print("9-----",change9)
		change+=change9
	if 10 in changed_postures_indices:
		change10 = analyse_AmmyyAdmin(changed_postures[parameter_names[10]])
		print("10-----",change10)
		change+=change10
	if 11 in changed_postures_indices:
		change11= analyse_Advanced_IPScanner(changed_postures[parameter_names[11]])
		print("11-----",change11)
		change+=change11
	return change
'''
def trust_score_change(old_params, new_params, old_score):
    
    changed_postures_indices = []

    print("YOOOOOO_______",len(old_params),"______",old_params)
    for i in range(len(old_params)):
        if old_params[parameter_names[i]] != new_params[parameter_names[i]]:
            changed_postures_indices.append(i)
    
    

    change = trust_calc(changed_postures_indices, new_params)

    trust_score = old_score + change

    if trust_score < 0 :
        trust_score = 0
    if trust_score > 1 :
        trust_score = 1
    
    return trust_score
'''

def initial_check(payload):
    device_postures = payload
    posture_indices = [i for i in range(len(device_postures))]
    trust_score = initial_trust_score(posture_indices, device_postures)
    global old_parameters
    old_parameters = device_postures
    if trust_score <= 0.5:
        revoked=True
    else:
        revoked=False
    print("----",trust_score)
    return revoked , trust_score
'''
def regular_check(payload, old_score):
    device_postures = payload
    global old_parameters
    trust_score = trust_score_change(old_parameters, device_postures, old_score)
    old_parameters = device_postures
    if trust_score <= 0.5:
        revoked=True
    else:
        revoked=False
    
    return revoked , trust_score
'''
#--------------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------------
#											Testing Functions
#--------------------------------------------------------------------------------------------------------

@csrf_exempt
def test_posture(request):
	#initalize payload dict
	payload = dict()

	if request.method == "POST":
		print("\nReceived Test Posture set.")
		#extracting payload
		#Note the payload key values have to match those set in the table_names list in agentreal.py
		payload = json.loads(request.body)
		print(payload.keys())
		uuid = payload["temp_uuid"]
		username = payload["username"]
		revoked, score = initial_check(payload)

		print("Revoked:",revoked)
		if(revoked==True):
			return HttpResponse("bad set received.")
		return HttpResponse("OK")

	return HttpResponse("Error! Get Req not allowed!!")

#--------------------------------------------------------------------------------------------------------
# from jwt.exceptions import InvalidSignatureError


# DB Initializers 
client =  MongoClient('localhost',27017)
db = client.mock
collection = db.deviceInfo

# JWT Secret 
key = 'secret'
URL = "127.0.0.1"

prev_good_posture = []

blacklisted_AddOns = []

# Get the static list 
#static_list = json.load(open("../static_list_linux.json"))
#static_list_items = list(static_list.keys())


#table_names = ["authorized_keys","block_devices","chrome_extensions","deb_packages","disk_encryption","etc_services","firefox_addons","interface_addresses","interface_details","kernel_info","kernel_modules","listening_ports","mounts","os_version","platform_info","processes","rpm_packages","shadow","system_info","usb_devices","users","temp_uuid","service","username"]

prev_payload_timestamp={}
TimeBetweenPayloads = 5

@csrf_exempt
def scheduledPayload(request):
	payload = dict()
	
	if request.method == "POST":

		payload = json.loads(request.body)

		uuid = payload["temp_uuid"]
		username = payload["username"]
		
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
		global old_score
		revoked, score = initial_check(payload)
		
		old_score=score

		usr_state = requests.post("http://192.168.0.153:8000/poll_usr_state/{}".format(uuid))

		if revoked == False and usr_state.text== 'active':
			print("posture good")
			return HttpResponse("YES")
		
		print("\nUser has logged out or has presented bad postures.")
		print("Terminating Scheduled-Payload Contract for User: ",uuid)

		res = requests.post("http://192.168.0.153:8001/cutOff/",headers={'uid':uuid},data={'ok':1})
		return HttpResponse("NO")

	else:
		return HttpResponse("GET not allowed!")

@csrf_exempt
def sso_login(request):

	#initalize payload dict
	payload = dict()

	if request.method == "POST":
		print("\nReceived Init Postures.")
		#extracting payload
		#Note the payload key values have to match those set in the table_names list in agentreal.py
		payload = json.loads(request.body)
		print(payload.keys())
		uuid = payload["temp_uuid"]
		username = payload["username"]
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