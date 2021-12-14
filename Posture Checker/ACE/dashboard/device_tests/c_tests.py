#--------------------------------------------------------------------------------------------------------#
#                                                                                                        #
#                                                                                                        #
#                                                                                                        #
#                            C-TEST  [Compliance Tests] Analytic Functions:                              #
#                                                                                                        #
#                                                                                                        #
#                                                                                                        #
#--------------------------------------------------------------------------------------------------------#

# Function Dependencies

from dashboard.models import Test1_Network_Applications,Test0_Startup_Items,Test2_Flagged_Browser_Extensions,Test3_Win_Sec_Center_Bad_States, Test6_OS_Versions,Test7_Windows_Hotfixes

from .configurations import threat

#--------------------------------------------------------------------------------------------------------

# Test Methods



# C-TEST-01: Browser Extensions Compliance
def C_TEST_01 (Browser_Extensions):

	flagged_extensions = [
		"Hola",
		"FindMeFreebies",
		"Hover Zoom",
		"AVG Online Security",
		"EasyToolOnline Promos",
		"LoveTestPro Ad Offers",
		"The Pirate Bay Torrent Search",
		"The Pirate Bay torrent Search"
	]

	modelResult = Test2_Flagged_Browser_Extensions.objects.filter()
	
	for e in modelResult:
		flagged_extensions.append(e.extensionName)

	count = 0

	for e in Browser_Extensions['name']:
		if e in flagged_extensions:
			count+=1
	
	if count>0:
		return count*threat["M"], str(count)+" bad extensions detected"

	return threat["OK"],"OK"



# C-TEST-02: Security Products Requirements
def C_TEST_02 (Sec_Products):

	if "Firewall" not in Sec_Products['type']:
		return threat["H"], "Firewall issue"
	
	if "Antivirus" not in Sec_Products['type']:
		return threat["H"], "Antivirus issue"

	return threat["OK"], "OK"



# C-TEST-03: Operating System Compliance
# --Allows all OS versions, need to connect to db.
def C_TEST_03 (OS_Version):
	return threat["OK"], "OK"



# C-TEST-04: Hotfixes Check
def C_TEST_04 (Hotfixes):

	diff=4-len(Hotfixes['hotfix_id'])
	
	if diff >0:
		return diff*threat["M"], str(diff)+" hotfixes missing"
	
	return threat["OK"], "OK"



# C-TEST-05: Flagged Application Check
# --need to implement

#--------------------------------------------------------------------------------------------------------

# Function Dispatcher

C_TEST_Dispatcher = {
	"C-Test-01": C_TEST_01,
	"C-Test-02": C_TEST_02,
	"C-Test-03": C_TEST_03,
	"C-Test-04": C_TEST_04
}