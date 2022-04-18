from shodan import Shodan

api = Shodan('Insert_your_Shodan_Api_Key')

# Lookup an IP
ipinfo = api.host('144.')
print(type(ipinfo))
print(ipinfo)
# Search for websites that have been "hacked"
for banner in api.search_cursor('http.title:"hacked by"'):
    print(banner)

# Get the total number of industrial control systems services on the Internet
ics_services = api.count('tag:ics')
print('Industrial Control Systems: {}'.format(ics_services['total']))
