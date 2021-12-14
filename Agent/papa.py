import sys
import os
import requests
import json
import ast
import osquery
IP='localhost'
data=''
json.dump(data,open("linux-final-data.json","w"))


headers = {"Content-type":"application/json","Accept":"text/plain"}
r = requests.post("http://{}:9001/submit/".format(IP),data=open("linux-final-data.json","rb"),headers=headers)

print(r.text)
