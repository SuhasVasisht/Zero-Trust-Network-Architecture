from django import forms
from django.forms.forms import Form

class testForm(forms.Form):
    testfield= forms.CharField(label='testfield', max_length=100)
    testfield= forms.CharField(label='testfield', max_length=100)
    testfield= forms.CharField(label='testfield', max_length=100)
    testfield= forms.CharField(label='testfield', max_length=100)
    testfield= forms.CharField(label='testfield', max_length=100)
    testfield= forms.CharField(label='testfield', max_length=100)
    testfield= forms.CharField(label='testfield', max_length=100)
    testfield= forms.CharField(label='testfield', max_length=100)
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