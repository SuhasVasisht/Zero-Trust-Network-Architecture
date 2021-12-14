
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import json 
import requests

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
		revoked, score = (False,0.75)#initial_check(payload)
		print("Revoked:",revoked)
		if(revoked==True):
			res = requests.post("http://192.168.0.153:8001/cutOff/",headers={'uid':uuid},data={'ok':1})
			return HttpResponse("bad set received.")
		return HttpResponse("OK")

	return HttpResponse("Error! Get Req not allowed!!")
