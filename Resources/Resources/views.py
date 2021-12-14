from django.shortcuts import render, redirect, HttpResponse
import uuid
from django.http import HttpResponseRedirect
import jwt
from django.views.decorators.csrf import csrf_exempt
import requests
currentUsers={}

@csrf_exempt
def logUserOut(request,uid):
	print("logging ",uid," out")
	currentUsers.pop(uid)
	print(currentUsers)
	return HttpResponse("OK")

@csrf_exempt
def cutOffUser(request):
	header_dict = dict(request.headers.items())
	#print(header_dict)
	badUid = header_dict.get("Uid")
	try:
		
		print("Bad Postures from UID:",badUid)
		print("cutting off access to UID:",badUid)

		currentUsers.pop(badUid)
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
		currentUsers[Uid] = permission
		#print(authenticatedUsers)
		return HttpResponse('User permission of ' + Uid + ' is effectively '+permission)
		
	except Exception as e:
		print(e)
		return HttpResponse("Error occured while updating permissions")

def codebase(request,uid):
    if uid not in currentUsers.keys():
        return HttpResponseRedirect("http://192.168.0.153:8001/dash/"+uid)

    perms = currentUsers[uid]
    permList = []

    if 'V' in perms:
        permList.append('View')
    if 'C' in perms:
        permList.append('Create')
    if 'M' in perms:
        permList.append('Modify')
    if 'D' in perms:
        permList.append('Delete')
    if 'd' in perms:
        permList.append('Download')

    return render(request,"codebase.html",{'uid':uid,'permList':permList})

def customerDatabase(request,uid):
    perms = currentUsers[uid]
    permList = []

    if 'V' in perms:
        permList.append('View')
    if 'C' in perms:
        permList.append('Create')
    if 'M' in perms:
        permList.append('Modify')
    if 'D' in perms:
        permList.append('Delete')
    if 'd' in perms:
        permList.append('Download')

    return render(request,"customerDatabase.html",{'uid':uid,'permList':permList})

def financialRecords(request,uid):
    perms = currentUsers[uid]
    permList = []

    if 'V' in perms:
        permList.append('View')
    if 'C' in perms:
        permList.append('Create')
    if 'M' in perms:
        permList.append('Modify')
    if 'D' in perms:
        permList.append('Delete')
    if 'd' in perms:
        permList.append('Download')

    return render(request,"financialRecords.html",{'uid':uid,'permList':permList})

def employeeRecords(request,uid):
    perms = currentUsers[uid]
    permList = []

    if 'V' in perms:
        permList.append('View')
    if 'C' in perms:
        permList.append('Create')
    if 'M' in perms:
        permList.append('Modify')
    if 'D' in perms:
        permList.append('Delete')
    if 'd' in perms:
        permList.append('Download')

    return render(request,"employeeRecords.html",{'uid':uid,'permList':permList})
