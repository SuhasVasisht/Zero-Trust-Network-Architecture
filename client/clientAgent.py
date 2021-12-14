import osquery
import requests
import json
from time import sleep
import sys

from requests.api import post
queries=[
    "select name, state,permissions,from_webstore from chrome_extensions",# 2 Browser Extensions (chrome)
    "select name, state, type, signatures_up_to_date FROM windows_security_products where state='On'", # 4 win sec products
    "select name, version, major, minor, patch, build from os_version;",# 6 Os versions
    "select hotfix_id, installed_on, caption from patches;", # 7 hotfix
]

parameter_names=[
	"C-Test-01",
	"C-Test-02",
	"C-Test-03",
	"C-Test-04",
]

columns=[
    ["name","state","permissions","from_webstore"],# 2 Browser_Exten
    ["name", "state", "type", "signatures_up_to_date"],# 4 win sec products
    ["name", "version", "major", "minor", "patch", "build"],# 6 OS ver
    ["hotfix_id", "installed_on", "caption"],# 7 hotfix
]

#gathers the postures, packages them.
def gatherPostures(client):
    
    postures = dict()
    #query='select name,status from startup_items'

    for table,query,column in zip(parameter_names,queries,columns):
        query_result = (client.query(query)).__dict__
        res = query_result['response']
        print(res)
        postures[table] = dict()
        for col in column:
            postures[table][col] = list()
    
        for row in res:
            for key, val in row.items():
                postures[table][key].append(val)
    
    postures["parameters"]=parameter_names
    postures["username"]=username
    postures["temp_uuid"]=uuid
    print(postures)
    return postures

#sends initial login postures.
def sendInitPostures(client):
    print("sending init postures")
    postures=gatherPostures(client)
    packaged_postures=json.dumps(postures)
    headers = {"Content-type":"application/json","Accept":"text/plain"}
    resp = requests.post("http://192.168.0.153:9001/submit/",packaged_postures,headers=headers)
    print(resp.text)
    return resp

#sends the scheduled payloads.
def sendScheduledPayload(client):
    postures=gatherPostures(client)
    packaged_postures=json.dumps(postures)
    headers = {"Content-type":"application/json","Accept":"text/plain"} 
    res = requests.post("http://192.168.0.153:9001/scheduled/",packaged_postures,headers=headers)
    return res

username=""
uuid=""


if __name__ == "__main__":

    args=sys.argv[1:]
    print(args)
    
    if len(args)!=1:
        sys.exit(0)
    
    service_name,uuid_details = args[0].split("://",1)[1].split("?",1)
    
    uuid = uuid_details.split("=",1)[1].split("&")[0]
    
    username=args[0].split("://")[1].split("?",1)[1].split("&")[1].split("=")[1]
    
    print(username)
    
    # You must know the Thrift socket path
    # For an installed and running system osqueryd, this is:
    #   Linux and macOS: /var/osquery/osquery.em
    #   FreeBSD: /var/run/osquery.em
    #   Windows: \\.\pipe\osquery.em
    instance = osquery.ExtensionClient()
    instance.open()  # This may raise an exception

    # Issue queries and call osquery Thrift APIs.
    client = instance.extension_client()
    #postures = gatherPostures(client)
    res = 'YES'
    res1 = sendInitPostures(client).text.split(':')
    if( res1[0] == 'YES'):
        while(True):
            sleep(int(res1[1]))
            if res == 'YES':
                r = sendScheduledPayload(client)
                res = r.text
            else:
                break
    else:
        print("Bad")
        a=input("press to exit")
    #res=(client.query('select distinct name from startup_items;').__dict__)
    #print(res)
    
    
#osqueryd --ephemeral --disable_logging --disable_extensions=false --extensions_socket="\\.\pipe\osquery.em"