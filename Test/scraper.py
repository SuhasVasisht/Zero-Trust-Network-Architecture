
import requests
from bs4 import BeautifulSoup
  
URL = "https://owasp.org/www-project-vulnerable-web-applications-directory/"
r = requests.get(URL)
  
soup = BeautifulSoup(r.content, 'html.parser')
table = soup.find('section', attrs = {'id':'sec-offline'})
offTable = list(table.children)[5]


badApps = []
filterWords = ["Download", "Downloads", "Guide", "Docker"]

result = offTable.find_all('a')
for row in result:
    app = row.text
    if app not in filterWords and '[' not in app:
        badApps.append(app)

print("Bad Applications:")
print(badApps)

'''
table2 = soup.find('section', attrs = {'id':'sec-online'})
onTable = list(table2.children)[5]

badWebs = []
filterWords = ["Download", "Downloads", "Guide", "Docker"]

result = onTable.find_all('a')
for row in result:
    site = row['href']
    if 'github' not in site:
        badWebs.append(site)
print("\n\n\nBad Websites:")
print(badWebs)
'''

badExtenstions = []
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36"}
extURL = "https://www.makeuseof.com/tag/unsafe-firefox-extensions/"
extr = requests.get(extURL,headers=headers)
extSoup = BeautifulSoup(extr.content, 'html.parser')
extTable = extSoup.find('article', attrs = {'class':'w-article article'})
extResult = extTable.find_all('h2')
for row in extResult:
    extension = row.text
    if "Beware" not in extension:
        badExtenstions.append(extension.strip()[3:])


print("\n\n\nBad Extensions:")    
print(badExtenstions)


