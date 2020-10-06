#!/usr/bin/python
import json
import requests
import warnings
import sys
from requests.auth import HTTPBasicAuth
import re


global pan_ip
global mnt_ip
global mnt_hostname
global admin_user
global admin_password
global default_group_name

### Update the info below
pan_ip = "x.x.x.x"
admin_user = 'admin'
admin_password = 'password'
mnt_hostname = 'mnt_fdqn'
mnt_ip = 'x.x.x.x'
default_endpointgroup_name = "Guests-2H"
### End of info update


base_url = "https://" + pan_ip + ":9060/ers/config/"

HEADERS = {
        'Accept': "application/json",
        'Content-Type': "application/json",
}

def main():

	#ignore invalid cert warnings
	warnings.filterwarnings("ignore")
	global endpointgroup_name

	if len(sys.argv) < 2:
		print('\nNo arguments entered. Exiting...\n')
		print_usage()
		sys.exit()

	if len(sys.argv) > 3:
		print('\nToo many arguments entered. Exiting...\n')
		print_usage()
		sys.exit()

	#If 2nd argrument is blank, use default EndPointGroup
	try:
		endpointgroup_name = sys.argv[2]
	except (IndexError):
		endpointgroup_name = default_endpointgroup_name
	print("\nGroup name to be used is " + endpointgroup_name + "\n")

	global client_ip
	global client_macaddress
	global client_name
	global client_id
	global endpointgroup_id
	client_ip = ''
	client_macaddress = ''
	client_name = ''
	client_id = ''
	endpointgroup_id = ''
	use_IP = True
	
	if valid_ip(sys.argv[1]) == True:
		client_ip = sys.argv[1]
		use_IP = True
		print("Use IP\n")
	elif valid_mac(sys.argv[1]) == True:
		print("Capitalizing and Colonizing MAC..." + sys.argv[1])
		client_macaddress = (sys.argv[1].upper()).replace("-", ":")   #Capitalize & Colonize
		print("Capitalized and Colonized MAC..." + client_macaddress + "\n")
		use_IP = False
		print("Use MAC\n")
	else:
		sys.exit()
	
	#If user enters IP, need to find MAC address from ISE
	if use_IP == True:
		client_macaddress = get_mac_from_ip()
		print ("IP " + client_ip + " MAC address is " + client_macaddress)
	
	#Get Client ID and Name using MAC address
	client_id, client_name = get_client_id_name_from_mac(client_macaddress)

	#Get EndPointGroup ID using name
	endpointgroup_id = get_endpointgroup_id(endpointgroup_name)

	#Assign Client to ISE EndPointGroup to default or user defined
	update_client_id_group()

	#Send Radius CoA to WLC/NAS to trigger re-auth and obtain new AuthZ profile
	send_coa(client_macaddress)

def print_usage():
	print('Usage: ' + str(sys.argv[0]) + ' <Client IP || MAC> [Group name]')
	print('  - Client IP or MAC address (HH:HH:HH:HH:HH:HH) must be entered')
	print('  - Group name is optional. Default group will be used if leave blank\n')

def valid_ip(ip_in_question):
	#print("Validing IP " + ip_in_question + "...")
	check_ip = re.search(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip_in_question)
	if bool(check_ip) == True:
		print("IP " + ip_in_question + "... is a valid IP. Continue...\n")
	else:
		print("IP " + ip_in_question + "... is NOT a valid IP. Check MAC...\n")
	return bool(check_ip)

def valid_mac(mac_in_question):
	#print("Validing MAC " + mac_in_question + "...")
	check_mac = re.search(r'^((([a-fA-F0-9]{2})[:-]){5}([a-fA-F0-9]{2}))$', mac_in_question)
	if bool(check_mac) == True:
		print("MAC " + mac_in_question + "... is a valid MAC. Continue...\n")
	else:
		print("MAC " + mac_in_question + "... is NOT a valid MAC. Exiting...\n")
	return bool(check_mac)

def get_mac_from_ip():
	try:
		mnt_url = "https://" + mnt_ip + "/admin/API/mnt/Session/EndPointIPAddress/" + client_ip
		#print ("\nGet Endpoint Info for ", client_ip + "\n")
		m = requests.get(url=mnt_url, auth=HTTPBasicAuth(admin_user,admin_password), verify=False)
		#print (m.text)
		calling_station_regex = re.compile(r'(<calling_station_id>)((([A-F0-9]{2}):){5}([A-F0-9]{2}))')
		calling_station = calling_station_regex.search(m.text)
		client_macaddress = calling_station.group(2)
		print ("Matched pattern is " + calling_station.group(0))
		return client_macaddress
	except (AttributeError):
		print("Unable to find MAC address from ISE. Exiting...\n")
		sys.exit()

def get_client_id_name_from_mac(client_macaddress):
	try:
		print("Getting client ID and name from MAC")
		API_URL_endpointinfo = base_url + "endpoint?filter=mac.EQ." + client_macaddress
		payload = {}
		r = requests.request("GET", API_URL_endpointinfo, auth=HTTPBasicAuth(admin_user,admin_password), headers=HEADERS, data=payload, verify=False)
		data = r.json()
		#print(data)
		#print ("Response code:" + str(r))
		print("client id of " + client_macaddress + " is " + data['SearchResult']['resources'][0]['id'])
		print("client name of " + client_macaddress + " is " + data['SearchResult']['resources'][0]['name'] + "\n")
		return data['SearchResult']['resources'][0]['id'],data['SearchResult']['resources'][0]['name']
	except (IndexError):
		print("Unable to find MAC address from ISE. Exiting...\n")
		sys.exit()

def get_endpointgroup_id(endpointgroup_name):
	try:
		print("Getting EndPointGroup ID for " + endpointgroup_name)
		API_URL_endpointgroupinfo = base_url + "endpointgroup/name/" + endpointgroup_name
		payload = {}
		r = requests.request("GET", API_URL_endpointgroupinfo, auth=HTTPBasicAuth(admin_user,admin_password), headers=HEADERS, data=payload, verify=False)
		#print ("Response code:" + str(r))
		data = r.json()
		#print(data)
		print("EndPointGroup id of " + endpointgroup_name + " is " + data['EndPointGroup']['id'] + "\n")
		return data['EndPointGroup']['id']
	except (json.decoder.JSONDecodeError):
		print("EndPointGroup id of " + endpointgroup_name + " cannot be found. Exiting..." + "\n")
		sys.exit()

def update_client_id_group():
	API_URL_endpoint = base_url + "endpoint/" + client_id
	API_DATA = ({
		'ERSEndPoint': {
		'id': client_id, 
		'name': client_name, 
		'mac': client_macaddress, 
		'profileId': '',
		'staticProfileAssignment': False, 
		'groupId': endpointgroup_id, 
		'staticGroupAssignment': True, 
		'portalUser': '', 
		'identityStore': '', 
		'identityStoreId': '', 
		'link': {
		'rel': 'self', 
		'href': base_url + '/endpoint/name/' + client_name, 
		'type': 'application/json'}}
	})
	print("Assigning Client name" + client_name + " to group " + endpointgroup_name + "\n")
	p = requests.request("PUT", API_URL_endpoint, auth=HTTPBasicAuth(admin_user,admin_password), headers=HEADERS, verify=False, json=API_DATA)
	payload = {}
	#r = requests.request("GET", API_URL_endpoint, auth=HTTPBasicAuth(admin_user,admin_password), headers=HEADERS, data=payload, verify=False)
	#data = r.json()
	#print(data)

def send_coa(client_macaddress):
	coa_url = "https://" + mnt_ip + "/admin/API/mnt/CoA/Reauth/" + mnt_ip + "/" + client_macaddress + "/1"
	print ("Sending CoA Reauth to ", client_macaddress)
	coa_result = requests.get(url=coa_url, auth=HTTPBasicAuth(admin_user,admin_password), verify=False)
	#print (coa_result.text)
	coa_success_regex = re.compile(r'(<results>true)')
	#print(coa_success_regex.search(coa_result.text))
	if coa_success_regex.search(coa_result.text) == None:
		print("CoA has failed for " + client_macaddress + "\n")
	else:
		print("CoA Successfully sent\n")
	

if __name__ == "__main__":
	main()