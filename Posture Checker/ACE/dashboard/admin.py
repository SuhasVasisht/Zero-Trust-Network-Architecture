from django.contrib import admin
from dashboard.models import Role,Employee, Test0_Startup_Items,Test1_Network_Applications,Test2_Flagged_Browser_Extensions,Test3_Win_Sec_Center_Bad_States,Test7_Windows_Hotfixes,Test6_OS_Versions

# Register your models here.

admin.site.site_header = 'Access Control Engine'
admin.site.site_title = 'Access Control Engine'
admin.site.site_url = None

admin.site.register(Employee)
admin.site.register(Role)

admin.site.register(Test0_Startup_Items)
admin.site.register(Test1_Network_Applications)
admin.site.register(Test2_Flagged_Browser_Extensions)
admin.site.register(Test3_Win_Sec_Center_Bad_States)
admin.site.register(Test6_OS_Versions)
admin.site.register(Test7_Windows_Hotfixes)
