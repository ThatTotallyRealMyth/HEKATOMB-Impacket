#!/usr/bin/env python3
#
# HEKATOMB - Because Domain Admin rights are not enough. Hack them all.
#
# AD LDAP Fonctions

import sys
from threading import *
import socket
import dns.resolver
from impacket.ldap import ldap, ldapasn1
import struct

global online_computers
online_computers = []

def scan(computer, domain, dns_server, port, debug, debugmax):
	# Trying to resolve IP address of the host
	screenLock = Semaphore(value=1)
	answer = ''

	# Create a socket object for TCP IP connection
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(30)

	try:
		# resolve dns to ip address
		resolver = dns.resolver.Resolver(configure=False)
		resolver.timeout = 60
		resolver.lifetime = 60
		resolver.nameservers = [dns_server]

		dns_computer = str(computer)+"."+str(domain)
		if debug is True or debugmax is True:
			screenLock.acquire()
			print("[+] Resolving "+str(dns_computer) + " by asking DNS server "+str(dns_server)+" ...")
			screenLock.release()

		# trying dns resolution in TCP and if it fails, we try in UDP
		answer = resolver.resolve(dns_computer, "A", tcp=True)
		if len(answer) == 0:
			answer = resolver.resolve(dns_computer, "A", tcp=False)
			if len(answer) == 0:
				screenLock.acquire()
				print("[!] DNS resolution for "+str(computer) + " has failed.")
				screenLock.release()
				sys.exit(1)
		else:
			if debug:
				screenLock.acquire()
				print ('[+] DNS resolution for ', str(computer) , ' succeeded : ',  str(answer[0]))
				screenLock.release()
		answer = str(answer[0])

	
		s.connect((answer, port))
		
	
		s.close()

		
		summary(computer)
		
	except Exception as e:
		if debug is True or debugmax is True:
			screenLock.acquire()
			print("[!] ERROR : " +str(e))
			screenLock.release()
	
	finally:
		screenLock.release()
		s.close()
		return



def SmbScan(computers_list, domain, dns_server, port, debug, debugmax):
	
	threads = []


	for computer in computers_list:

		
		t = Thread(target=scan, args=(computer, domain, dns_server, port, debug, debugmax))

	
		t.start()

		
		threads.append(t)
	
	
	[t.join() for t in threads]
	return




def summary(computer):
	online_computers.append(computer)
	return

def Get_online_computers():
	return online_computers


def _format_sid(sid_bytes):
	if not sid_bytes:
		return ""
	revision = sid_bytes[0]
	sub_authority_count = sid_bytes[1]
	identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')
	sub_authorities = struct.unpack('<' + 'I' * sub_authority_count, sid_bytes[8:8 + (sub_authority_count * 4)])
	return f"S-{revision}-{identifier_authority}-" + "-".join([str(sub) for sub in sub_authorities])

def _impacket_search(ldapConnection, baseDN, searchFilter, attributes):
	try:
		resp = ldapConnection.search(searchBase=baseDN, searchFilter=searchFilter, attributes=attributes, sizeLimit=0)
	except ldap.LDAPSearchError as e:
		resp = e.getAnswers()
	
	results = []
	for item in resp:
		if isinstance(item, ldapasn1.SearchResultEntry):
			result_dict = {}
			for attribute in item['attributes']:
				attr_type = str(attribute['type'])
				attr_val = attribute['vals'][0]
				result_dict[attr_type] = attr_val
			results.append(result_dict)
	return results


def Connect_AD_ldap(address, domain, username, password, lmhash, nthash, doKerberos, dc_ip, debug, debugmax):
	if debug is True or debugmax is True:
		print("[+] Testing LDAP connection...")

	# Use standard ldap:// over port 389. SASL will negotiate integrity.
	target_host = domain if domain else address

	try:
		ldapConnection = ldap.LDAPConnection(f'ldap://{target_host}', '', dc_ip)
		
		if doKerberos:
			if debug is True or debugmax is True:
				print("[+] Authenticating with Kerberos (SASL)...")
			ldapConnection.kerberosLogin(username, password, domain, lmhash, nthash, '', kdcHost=dc_ip)
		else:
			if debug is True or debugmax is True:
				print("[+] Authenticating with NTLM (SASL)...")
			ldapConnection.login(username, password, domain, lmhash, nthash)
			
		if debug is True or debugmax is True:
			print("[+] LDAP connection and SASL authentication succeeded!")
	except Exception as e:
		print(f"[!] Error : Could not connect to ldap or authenticate. {str(e)}")
		if debug is True or debugmax is True:
			import traceback
			traceback.print_exc()
		sys.exit(1)

	# Dynamically extract baseDN from RootDSE
	try:
		resp = _impacket_search(ldapConnection, '', '(objectClass=*)', ['defaultNamingContext'])
		if resp and 'defaultNamingContext' in resp[0]:
			base_val = resp[0]['defaultNamingContext']
			baseDN = base_val.decode('utf-8') if isinstance(base_val, bytes) else str(base_val)
		else:
			baseDN = ','.join(['DC=' + x for x in domain.split('.')])
	except Exception:
		baseDN = ','.join(['DC=' + x for x in domain.split('.')])

	return ldapConnection, baseDN


def Get_AD_users(ldapConnection, baseDN, just_user, debug, debugmax):
	if just_user is not None:
		searchFilter = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={just_user}))"
		print("[+] Target user will be only " + str(just_user))
	else:
		searchFilter = "(&(objectCategory=person)(objectClass=user))"
	
	print("[+] Retrieving user objects in LDAP directory...")
	ldap_users = []
	try:
		results = _impacket_search(ldapConnection, baseDN, searchFilter, ['sAMAccountName', 'objectSid'])
		if debug is True or debugmax is True:
			print("[+] Converting ObjectSID in string SID...")
			
		for res in results:
			if 'sAMAccountName' in res and 'objectSid' in res:
				uname_raw = res['sAMAccountName']
				uname = uname_raw.decode('utf-8') if isinstance(uname_raw, bytes) else str(uname_raw)
				sid = _format_sid(res['objectSid'])
				ldap_users.append([uname.strip(), sid])
				
		if debug is True or debugmax is True:
			print("[+] Found about " + str(len(ldap_users)) + " users in LDAP directory.")
	except Exception as e:
		print("[!] Error : Could not extract users from ldap.")
		if debug is True or debugmax is True:
			import traceback
			traceback.print_exc()
		sys.exit(1)

	if len(ldap_users) == 0:
		print("[!] No user found in LDAP directory")
		sys.exit(1)
	
	return ldap_users


def Get_AD_computers(ldapConnection, baseDN, just_computer, debug, debugmax):
	print("[+] Retrieving computer objects in LDAP directory...")
	ad_computers = []
	if just_computer is not None:
		ad_computers.append(just_computer)
		print("[+] Target computer will be only " + str(just_computer))
	else:
		try:
			searchFilter = "(&(objectCategory=computer)(objectClass=computer)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
			results = _impacket_search(ldapConnection, baseDN, searchFilter, ['name', 'cn'])
			
			for res in results:
				name_val = res.get('cn') or res.get('name')
				if name_val:
					comp_name = name_val.decode('utf-8') if isinstance(name_val, bytes) else str(name_val)
					ad_computers.append(comp_name.strip())
					
			if debug is True or debugmax is True:
				print("[+] Found about " + str(len(ad_computers)) + " computers in LDAP directory.")
		except Exception as e:
			print("[!] Error : Could not extract computers from ldap.")
			if debug is True or debugmax is True:
				import traceback
				traceback.print_exc()
				
	return list(set(ad_computers))