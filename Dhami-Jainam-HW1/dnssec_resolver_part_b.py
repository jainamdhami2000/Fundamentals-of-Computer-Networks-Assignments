# -*- coding: utf-8 -*-

import dns.message, dns.query, dns.resolver, dns.dnssec, dns.rdataclass, dns.rdatatype, dns.query
import cryptography
import time
import datetime
import math
import sys 
import copy

ROOTS = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241'] ## written till f
#   Returns the Algorithm name based on the digest type of DS value
digest_kind = {1:'SHA1', 2: 'SHA256', 3: 'SHA384'}

def getrootserverlist():
		# List of Root Servers
    root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']
    return root_servers

def TwoStepValidation(domain, hash, dslist, RR_sig, RR_set):
	# In the first step verify the hash with parent ds
	verified_hash = False;
	for ds in dslist:
		if ds == hash:
			verified_hash = True

	if not verified_hash:
		print("DNSSec verification failed")
		return False

	#In the next step, if the ds has matched, check for validating the public key
	try:
		dns.dnssec.validate(RR_set, RR_sig, {dns.name.from_text(domain): RR_set})
	except dns.dnssec.ValidationFailure:
		print("DNSSec verification failed")
		return False
	return True

def get_nextlevelservers(domain, server):
	# This is the Function to get the next level domain
	response = sendqueryudp(domain, dns.rdatatype.DNSKEY, server, True)
	if not response:
		return None

	child_ds = None
	child_hash_fn = None
	
	if len(response.authority) > 0:
		# DS field of authorative section is extracted for hashing algorithm and child
		for auth in response.authority:
			if (auth.rdtype == dns.rdatatype.DS):
				child_ds = auth[0]
				if (auth[0].digest_type == 1):
					child_hash_fn = "sha1"
				elif (auth[0].digest_type == 2):
					child_hash_fn = "sha256"
				break

	#if an answer section is found or there is soa type in authority field return 
	if (len(response.answer) > 0 or ((len(response.authority) > 0) and (response.authority[0].rdtype == dns.rdatatype.SOA))):
		return [server], child_ds, child_hash_fn
	
	#If the above is not the case check for the addition fields first as they might have direct IPs
	res = []
	if(len(response.additional) > 0):
		for add in response.additional:
			res.append(add[0].to_text())
	if res:
		return res, child_ds, child_hash_fn

	#If none hit above check for authority section as ot might have some authoritative NS and resolve it like previous
	if len(response.authority) > 0:
		#pick the first authoritative server ;to do: check for other ns if any fails
		if len(response.authority[0]) > 0:
			authoritative_ns = response.authority[0][0].to_text()
	if authoritative_ns:	
		return resolve(authoritative_ns), child_ds, child_hash_fn

	return [], None, None

def sendqueryudp(domain, dnstype, toserver, dnssecflag):
	try:
		query = dns.message.make_query(domain, dnstype, want_dnssec = dnssecflag)
		return dns.query.udp(query, toserver, timeout=10)
	except:
		return None

def Get_RRSig_RRSet_Key(domain, server):
	response = sendqueryudp(domain, dns.rdatatype.DNSKEY, server, True)
	
	if not response:
		return None
	# Extract the RR_sig
	RR_sig = None
	if len(response.answer) == 0:
		RR_sig = None
	else:
		for entry in response.answer:
			if (entry.rdtype == dns.rdatatype.RRSIG):
				RR_sig = entry
				break

	# Extract the RR_set, Key(KSK)
	RR_set, KSK = None, None
	if len(response.answer) == 0:
		RR_set, KSK = None, None
	else:
		for entry in response.answer:
			if (entry.rdtype == dns.rdatatype.DNSKEY):
				for record in entry:
					if record.flags == 257:   #257 is KSK, 256 is ZSK
						RR_set, KSK = entry, record

	return RR_sig, RR_set, KSK

def populate_nextlevel_servers(servers_currlevel, query):
	for server in servers_currlevel:
		try:
			nextLevelServers, child_ds, child_hash_fn = get_nextlevelservers(query, server)
			if (nextLevelServers):
				return nextLevelServers, child_ds, child_hash_fn
		except:
			pass

	return [], None, None

def resolve(domain):

	domain_splits = domain.split('.')
	domain_splits = domain_splits[::-1]
	query = domain_splits[0]+'.'

	RR_set = None
	child_ds = None
	child_hash_fn = None

# Handling ROOT          
	for rootserver in getrootserverlist():
		root_dslist = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5', '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']
		
		response = sendqueryudp('.', dns.rdatatype.DNSKEY, rootserver, True)

		if not response:
			return None
		
		RR_sig = None
		if len(response.answer) == 0:
			RR_sig = None
		else:
			for entry in response.answer:
				if (entry.rdtype == dns.rdatatype.RRSIG):
					RR_sig = entry
					break

		RR_set, KSK = None, None
		if len(response.answer) == 0:
			RR_set, KSK = None, None
		else:
			for entry in response.answer:
				if (entry.rdtype == dns.rdatatype.DNSKEY):
					for record in entry:
						if record.flags == 257:   #257 is KSK, 256 is ZSK
							RR_set, KSK = entry, record
	
		if not KSK or not RR_sig or not RR_set:
			return None

		hash = dns.dnssec.make_ds('.', KSK, 'sha256')
		
		if TwoStepValidation('.', str(hash), root_dslist, RR_sig, RR_set):  
			RR_set, child_ds, child_hash_fn = get_nextlevelservers(query, rootserver)
			if RR_set:
				break

	servers_currlevel, child_ds, child_hash_fn = RR_set, child_ds, child_hash_fn

	# Handling other zones/servers
	for domain in domain_splits[1:]:
		KSK = None
		RR_set = None
		RR_sig = None

		for server in servers_currlevel:
			RR_sig, RR_set, KSK = Get_RRSig_RRSet_Key(query, server)
			
			if KSK and RR_sig and RR_set:
				break

		validation_state = False
		if child_hash_fn and child_ds and KSK and RR_sig:
				hash_key = dns.dnssec.make_ds(query, KSK, child_hash_fn)
				validation_state = TwoStepValidation(query, hash_key, [child_ds], RR_sig, RR_set)
		else:
			print( "DNSSEC failed")

		if not validation_state:
			return None

		query = domain + '.' + query
		if not servers_currlevel:
			break
		
		nextlevelServers, child_ds, child_hash_fn = populate_nextlevel_servers(servers_currlevel, query)
		servers_currlevel = nextlevelServers

	return servers_currlevel

def rootserverlooper(domain):
	servers = resolve(domain)

	if not servers:
		return None

	for server in servers:
		result = sendqueryudp(domain, "A", server, False)
		if result:
			return result
	return None

def mydig(domain):
	res = rootserverlooper(domain)
	if res:
		print(res.answer[0][0])
	else:
		print("DNS verification failed")

domain_name = sys.argv[1]
mydig(domain_name)