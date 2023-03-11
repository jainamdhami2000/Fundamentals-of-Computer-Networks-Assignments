# -*- coding: utf-8 -*-

#Import the libraries
import dns.resolver, dns.query, time, datetime, sys
original_domain = ''

#Send udp query
def sendqueryudp(domain, dnstype, torootserver):
  q = dns.message.make_query(domain, dnstype)	
  return dns.query.udp(q, torootserver)

#Fetching a list of root servers
def getrootservers():
    root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']
    return root_servers

#Loop to iterate over all the root servers

def rootserverloop(domain, dnstype, cname):
  for i in getrootservers():
    ans, cname, torootserver = resolve(domain, dnstype, i, cname)
    if ans:
      return ans[0]

#The DNS resolver

def resolve(domain, dnstype, torootserver, cname):
  response = sendqueryudp(domain, dnstype, torootserver)
  global original_domain
  
  # Resolving Response.answer
  if response.answer:
    response_answer = response.answer
    # Handling cname
    if 'CNAME' in response_answer[0].to_text():
      new_domain = response_answer[0][0].to_text()
      cname = True
      for i in getrootservers():
        response_answer, cname, torootserver = resolve(new_domain, dnstype, i, cname)
        return response_answer, cname, torootserver
    return response_answer, cname, torootserver

  # Resolving Response.additional
  elif response.additional:
    # Filtering out all ipv4 addresses
    iplist = []
    for j in range(len(response.additional)):
      if 'AAAA' in response.additional[j].to_text():
        continue
      iplist.append(response.additional[j][0].to_text())
    for j in iplist:
      response_additional, cname, torootserver = resolve(domain, dnstype, j, cname)
      if response_additional:
        break
    return response_additional, cname, torootserver
  
  # Resolving Response.authority
  elif response.authority:
    # Handling SOA
    if 'SOA' in response.authority[0].to_text():
      global original_domain
      if ('www' in original_domain) or (cname and (dnstype == 'MX' or dnstype == 'NS')):
        return response.authority, cname, torootserver
      else:
        ans, cname, torootserver = resolve(original_domain, dnstype, torootserver, cname)
        return ans, cname, torootserver
      
    authlist = []
    for j in range(len(response.authority)):
      authlist.append(response.authority[0][j].to_text())
    root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']
    for i in root_servers:  
      for j in authlist:
        response_authority, cname, torootserver = resolve(j, dnstype, i, cname)
        return response_authority, cname, torootserver

def mydig():
  domain = sys.argv[1]
  global original_domain
  original_domain = domain
  dnstype = sys.argv[2]
  start = time.process_time()
  cname = False
  ans = rootserverloop(domain, dnstype, cname)
  end = time.process_time()
  date = datetime.datetime.now()
  
  print('\nQUESTION SECTION:')
  print(domain, ' IN ', dnstype, '\n')
  print('ANSWER SECTION:')
  print(domain, ' IN ', dnstype, ' ', ans[0])
  print("\nQuery time " + "{:.10f}".format(end-start) + "s")
  print('WHEN', date)
  print('MSG SIZE rcvd: ', sys.getsizeof(ans))

mydig()

