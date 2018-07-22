import socket
import re
import json

def getServer(address):
  if address.replace('.', '').isnumeric():
    return 'whois.lacnic.net'
  else:
    address = re.sub('^((http|ftp)s?)://', '', address)
    if address.endswith('com') or address.endswith('net'):
      return 'whois.verisign-grs.com'
    elif address.endswith('br'):
      return 'whois.nic.br'
    else:
      exit('Not supported :(')

def whois(address):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server = (getServer(address), 43)
  sock.connect(server)
  sock.settimeout(3)
  target = address + '\r\n'
  sock.sendall(target.encode())
  data = ''
  while True:
    contents = sock.recv(1024)
    if not contents: break
    data += str(contents.decode())
  sock.close()
  return data

def parseWhoisData(target):
  return ''.join([item for item in target]).replace('   ', '').split('\n')

def extract(data):
  data = parseWhoisData(data)
  intel = []
  for line in data:
    if ':' in line and '%' not in line:
      line = line.split(':')
      intel.append(line)
  return intel

def whoisBrToJson(data):
  untreated = {}
  tmpDns = []
  tmpCon = []
  dns = {}
  con = {}
  print(data)
  for (k, v) in data:
    if k in ['nserver', 'nsstat', 'nslastaa']:
      if k in dns.keys():
        tmpDns.append(dns)
        dns = {}
      dns[k] = v
    elif k in ['nic-hdl-br', 'person', 'e-mail']:
      if k in con.keys():
        tmpCon.append(con)
        con = {}
      con[k] = v
    elif k in ['country', 'created', 'changed', 'provider'] and k in untreated:
      if k not in con.keys():
        con[k] = v
    else:
      if len(dns) > 0:
        tmpDns.append(dns)
        dns = {}
        untreated['dns'] = tmpDns
        tmpDns = []
      untreated[k] = v

  if len(con) > 0:
    tmpCon.append(con)
    con = {}
    untreated['contacts'] = tmpCon
    tmpCon = []
  return json.dumps(untreated)

if __name__ == '__main__':
  header = "***************\n WHOIS DUMP\n***************\n\n"
  text = "Please, input a domain: "
  domain = input(header + text)
  dump = whois(domain)
  intel = extract(dump)
  print(whoisBrToJson(intel))
