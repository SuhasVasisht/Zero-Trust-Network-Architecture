#--------------------------------------------------------------------------------------------------------#
#                                                                                                        #
#                                                                                                        #
#                                                                                                        #
#                            H-TEST [Device Health Tests] Analytic Functions:                            #
#                                                                                                        #
#                                                                                                        #
#                                                                                                        #
#--------------------------------------------------------------------------------------------------------#

# Function Format:
# Accepts the respective parameter, anayses them and returns a threat level and message output.


# Function Dependencies

from dashboard.models import Test1_Network_Applications

from .configurations import threat

#--------------------------------------------------------------------------------------------------------

# # Test Methods



# H-TEST-01: Processes Spawning cmd.exe
def H_TEST_01 (parent_process):
	
	count = 0
	
	known_signatures=["Outlook.exe","Adobe Reader.exe"]
	normal_signatures=["explorer.exe","cmd.exe"]

	for p in parent_process["name"]:
		count+=1
		if p in normal_signatures:
			count-=1

		if p in known_signatures:
			return threat["H"], "Potential Malicious Process Spawning cmd.exe"
	
	if count == 0:
		return threat["OK"], "OK"
	
	return count*threat["M"], "Abnormal Parent Process Spawning cmd.exe"



#H-TEST-02: Suspicious Run Locations
def H_TEST_02 (processes):
	
	count=0
	
	for p in processes["name"]:
		count+=1

	if count == 0:
		return threat["OK"], "OK"
	
	return count*threat["L"], "Processes running from known abnormal locations."



#H-TEST-03: Execution with AT
def H_TEST_03 (par):
	return threat["OK"], "OK"



#H-TEST-04: Powershell Execution
def H_TEST_04 (par):
	return threat["OK"], "OK"



#H-TEST-05: Services launching Cmd
def H_TEST_05 (par):
	return threat["OK"], "OK"


#H-TEST-06: Remote PowerShell Sessions
def H_TEST_06 (par):
	return threat["OK"], "OK"



#H-TEST-07: Common Windows Process Masquerading
def H_TEST_07 (par):
	return threat["OK"], "OK"


#H-TEST-08: Batch File Write to System32
def H_TEST_08 (par):
	return threat["OK"], "OK"



#H-TEST-09: Webshell-Indicative Process Tree
def H_TEST_09 (par):
	return threat["OK"], "OK"



# H-TEST-10: CMSTP Setting Up Listeners.
def H_TEST_10 (par):
	return threat["OK"], "OK"



# H-TEST-11: Processes with Deleted Binaries
def H_TEST_11 (Prog_WO_Binaries):
	
	if len(Prog_WO_Binaries['name'])>0:
		return threat["H"], str(len(Prog_WO_Binaries['name']))+" programs without binaries detected"

	return threat["OK"], "OK"



# H-TEST-12: Custom: Network Application Test
def H_TEST_12 (Network_Apps):

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
				return threat["H"],"Bad Network Application Detected"
	
	return threat["OK"],"OK"



# H-TEST-13: Custom: Security Services Status 
def H_TEST_13(Win_Sec_Center):

	badset=["Poor","Not Monitored","Error","Snoozed"]
	#print("-------",Win_Sec_Center['antivirus'])
	#modelResult = Test3_Win_Sec_Center_Bad_States.objects.all()
	
	badset=[]
	'''
	for e in modelResult:
		badset.append(e.stateName)
	'''

	if Win_Sec_Center['firewall'][0] in badset:
		return threat["H"], "Firewall issue"

	if Win_Sec_Center['antivirus'][0] in badset:
		return threat["M"], "Antivirus issue"

	if Win_Sec_Center['internet_settings'][0] in badset:
		return threat["H"], "Internet settings issue"

	if Win_Sec_Center['antispyware'][0] in badset:
		return threat["H"], "Antispyware issue"
	
	count = 0 
	if Win_Sec_Center['user_account_control'] in badset:
		count+=1
	
	if Win_Sec_Center['autoupdate'] in badset:
		count+=1
	
	if count>0:
		return count*threat["M"], "Bad autoupdate setting"

	return threat["OK"], "OK"

#--------------------------------------------------------------------------------------------------------

# Function Dispatcher

H_TEST_Dispatcher = {
	
	"H-Test-01":H_TEST_01,
	"H-Test-02":H_TEST_02,
	"H-Test-03":H_TEST_03,
	"H-Test-04":H_TEST_04,
	"H-Test-05":H_TEST_05,
	"H-Test-06":H_TEST_06,
	"H-Test-07":H_TEST_07,
	"H-Test-08":H_TEST_08,
	"H-Test-09":H_TEST_09,
	"H-Test-10":H_TEST_10,
	"H-Test-11":H_TEST_11,
	"H-Test-12":H_TEST_12,
	"H-Test-13":H_TEST_13,
}