#test file for postures.

import requests


headers = {"Content-type":"application/json","Accept":"text/plain"}

resp = requests.post("http://192.168.0.153:9001/test_posture/",data=open('Test/data.json',"rb"),headers=headers)

print(resp.text)

a=input("Press any key to exit...")