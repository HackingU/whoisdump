import pythonwhois
import json
import datetime

def getWhois(domain):
  if domain.endswith('.com') or domain.endswith('net'):
    request = pythonwhois.net.get_whois_raw(domain, 'whois.publicdomainregistry.com')
    if request[0].startswith('Whois Error'):
      request = pythonwhois.get_whois(domain)
  else:
    request = pythonwhois.net.get_whois_raw(domain)
  return parse(request)
  
def parse(data):
  return pythonwhois.parse.parse_raw_whois(data)

def getContacts(data):
  contacts = {}
  for key, value in data['contacts'].items():
    if value != None:
      contacts[key] = value
  return contacts

if __name__ == '__main__':
  header = "***************\n WHOIS DUMP\n***************\n\n"
  text = "Please, input a domain: "
  print(header)
  domain = str(input(text))
  parsedWhois = getWhois(domain)
  contacts = getContacts(parsedWhois)
  print(parsedWhois)
  print()
  for typeContact, contactData in contacts.items():
    print('**********************\n* {} :'.format(typeContact))
    for k, v in contactData.items():
      print(k, ':', v)
    print('\n')
