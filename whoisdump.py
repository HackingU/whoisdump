import socket
import re

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
  data = []
  while True:
    contents = sock.recv(1024)
    if not contents: break
    data.append(contents)
  sock.close()
  return data

def parseWhoisData(target):
  return ''.join([item.decode() for item in target]).replace('   ', '').split('\r\n')

if __name__ == '__main__':
  domain = 'hackingu.net'
  dump = whois(domain)
  data = parseWhoisData(dump)
  print(data)
