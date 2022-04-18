import shodan
import requests
from shodan import Shodan

'''
api = Shodan('Insert_your_Shodan_Api_Key')
print(api.search(query='product:nginx', facets='country,org'))
'''

SHODAN_API_KEY = "Insert_your_Shodan_Api_Key"
api = shodan.Shodan(SHODAN_API_KEY)

target = 'www.packtpub.com'

dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY
Data={}
try:
    # First we need to resolve our targets domain to an IP
    resolved = requests.get(dnsResolve)
    hostIP = resolved.json()[target]

    # Then we need to do a Shodan search on that IP
    host = api.host(hostIP)
    Data['Ip']=host['ip_str']
    Data['Organization']=host.get('org')
    Data['Operating System']=host.get('OS')
    #print ("IP: %s" % host['ip_str'])
    #print ("Organization: %s" % host.get('org', 'n/a'))
    #print ("Operating System: %s" % host.get('os', 'n/a'))

    # Print all banners
    for item in host['data']:
        Data['Port']=item['port']
        Data['Banner']=item['data']
        #print ("Port: %s" % item['port'])
        #print ("Banner: %s" % item['data'])

    # Print vuln information
    for item in host['vulns']:
        CVE = item.replace('!','')
        Data['Vulnerability']=item
        print ('Vulns: %s' % item)
        exploits = api.exploits.search(CVE)
        for item in exploits['matches']:
            if item.get('cve')[0] == CVE:
                Data['Description']=item.get('description')
                print (item.get('description'))
except:
    'An error occured'
