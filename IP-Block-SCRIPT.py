# The below script performs ip address Block on Cisco routers and ASA
# The ip address to be blocked are checked against a reference ip address
# list which consists of IP addresses you dont want to block
# The script also checks if the provided ip addresses are valid
# by performing many different checks


# Base file Created on: 14th May 2020
# Updated on: 18th May 2020

# Version-1: The version 1 included additional checks on the ip addressess
#            from the ENTER_COMPANY_NAME_HERE reference ip address file	 
# Version-2: The version 2 changed the firewall, ios-xe, ios-xr TEXT files
#			 to CSV files
# Version-3: The version 3 changed the reference ip address TEXT file
#			 to the CSV file. It also captures and emails the script summary


# Script Pre-requisites to run:
# 1. Install netmiko and paramiko module 
# 2. Install netaddr module
# 3. Install ipaddr module



import getpass
import sys
import os
import shutil
import telnetlib
import time
from datetime import datetime
import socket
import paramiko
import netmiko
import netaddr
from netaddr import *
from netmiko import ConnectHandler
import ipaddress
import logging
import ftplib
import smtplib
from socket import gaierror
import csv


# Define the London FTP server parameters
ftp_lon_srvr_ip = "ENTER_FTP_SERVER_IP"
ftp_lon_srvr_user = "ENTER_FTP_USERNAME_HERE"
ftp_lon_srvr_password = "ENTER_FTP_PASSWORD_HERE"
ftp_lon_srvr_port = 21


ipblckcount = 0 # Counts the number of ip addresses in the ip block file
ipblckentry = 0 # Runs through the ip block entry in sequence
incr_ipblckcount = 1 # Used to assign sequence numbers to ACL entries


prblm_ip_count = 0 # Counts the problematic ip addresses in the ip block file
prblm_ip_ipblock = "" # Stores the lis of problem ip addresses


prblm_fw = "" # Keeps track of firewalls on which the commands were not executed
prblm_fw_count = 0 # Keeps track no. of failed firewall config execution

prblm_rtr = "" # Keeps track of routers on which the commands were not executed
prblm_rtr_count = 0 # Keeps track no. of failed routers config execution


ipexcp = 0 # Used to refer exceptions if ip block subnet of reference subnet and vice versa
refexcp = 0 # Used to refer exceptions if ip block subnet of reference subnet and vice versa


fw_imp_conf = "" # Used to store firewall implementation config
fw_roll_conf = "" # Used to store firewall rollback  config


rtr_xe_imp_conf = "" # Used to store router IOS-XE implementation config
rtr_xe_roll_conf = "" # Used to store router IOS-XE rollback config


rtr_xr_imp_conf = "" # Used to store router IOS-XR implementation config
rtr_xr_roll_conf = "" # Used to store router IOS-XR rollback config


config_scrpt_log = "" # Used to store the config creation script logs


exec_fw_scrpt_log = "" # Used to store the fw config execution script logs
exec_rtr_xe_scrpt_log = "" # Used to store the ios-xe config execution script logs
exec_rtr_xr_scrpt_log = "" # Used to store the ios-xr config execution script logs


exec_fw_eachrun = "" # Used to display the config of the firewall 
exec_rtr_xe_eachrun = "" # Used to display the config of the ios-xe router 
exec_rtr_xr_eachrun = "" # Used to display the config of the ios-xr router 


config_start_time = datetime.now() # Used to store the config script start time
fw_start_time = datetime.now() # Used to store the fw exec script start time
rtr_xe_start_time = datetime.now() # Used to store the ios-xe router exec script start time
rtr_xr_start_time = datetime.now() # Used to store the ios-xr router exec script start time


log_file_datestr = "" # Used to store the date for script log file
config_datestr = "" # Used to store the date for config script log file
fw_datestr = "" # Used to store the date for firewall log file
rtr_xe_datestr = "" # Used to store the date ios-xe router for log file
rtr_xr_datestr = "" # Used to store the date ios-xr router for log file


# Belos block logs the netmiko connections to fw and routers
log_file_datestr = time.strftime("_%d_%m_%Y")
log_filename = "IP-Block-Scrpt_debug_log" + str(log_file_datestr) + ".txt"
logging.basicConfig(filename=log_filename, level=logging.DEBUG)
logger = logging.getLogger("netmiko")


# Use the netaddr module to obtain the default network details
dfltntwk = IPNetwork("0.0.0.0/0")
net_dfltntwk = IPNetwork("0.0.0.0/0").network
ip_dfltntwk = IPNetwork("0.0.0.0/0").ip
nmask_dfltntwk = IPNetwork("0.0.0.0/0").netmask
wldcrdmask_dfltntwk = IPNetwork("0.0.0.0/0").hostmask
prfxlen_dfltntwk = IPNetwork("0.0.0.0/0").prefixlen


# Use the netaddr module to obtain the Loopback network details
loopbckntwk = IPNetwork("127.0.0.0/8")
net_loopbckntwk = IPNetwork("127.0.0.0/8").network
ip_loopbckntwk = IPNetwork("127.0.0.0/8").ip
nmask_loopbckntwk = IPNetwork("127.0.0.0/8").netmask
wldcrdmask_loopbckntwk = IPNetwork("127.0.0.0/8").hostmask
prfxlen_loopbckntwk = IPNetwork("127.0.0.0/8").prefixlen


# Below FOR loop is to count the ip addresses in the IP block file
with open('IP-Block-list.txt') as countipblock:
	for lineipblock in countipblock:
		x = lineipblock.strip()
		x = lineipblock.rstrip()
		if x != "":
			ipblckcount = ipblckcount + 1
			

# Using the variable ipblckcount to read the number of entries provided to block
# in the ip address block file	
config_scrpt_log = config_scrpt_log + "\n *************************************************"		
config_scrpt_log = config_scrpt_log + "\n The total ip addresses provided for blocking are: " + str(ipblckcount) + "\n"
config_scrpt_log = config_scrpt_log + " *************************************************\n"		

print ("\n The total ip addresses provided for blocking are: " + str(ipblckcount))		


diff_ipblckcount = ipblckcount +10 # Used as increement counter for router ACL


# Saves the initial firewall commands to the implementation and rollback config
fw_imp_conf = fw_imp_conf + "\nterminal page 0" + "\nterminal width 511" + "\nsh clock" + "\nobject-group network ACL-PYTHON-SCRIPT-TEST \n"
fw_roll_conf = fw_roll_conf + "\nterminal page 0" + "\nterminal width 511" + "\nsh clock" + "\nobject-group network ACL-PYTHON-SCRIPT-TEST \n"
	

# Saves the initial router ios-xe commands to the implementation and rollback config
rtr_xe_imp_conf = rtr_xe_imp_conf + "\ndo terminal len 0" + "\ndo terminal width 511" + "\ndo sh clock" + "\nip access-list resequence ACL-PYTHON-SCRIPT-TEST 1 " + str(diff_ipblckcount) + "\n"
rtr_xe_imp_conf = rtr_xe_imp_conf + "\nip access-list extended ACL-PYTHON-SCRIPT-TEST \n"

rtr_xe_roll_conf = rtr_xe_roll_conf + "\ndo terminal len 0" + "\ndo terminal width 511" + "\ndo sh clock" + "\nip access-list extended ACL-PYTHON-SCRIPT-TEST \n"


# Saves the initial router ios-xr commands to the implementation and rollback config
rtr_xr_imp_conf = rtr_xr_imp_conf + "\ndo terminal len 0" + "\ndo terminal width 511" + "\ndo sh clock" + "\nobject-group network ipv4 ACL-PYTHON-SCRIPT-TEST\n"

rtr_xr_roll_conf = rtr_xr_roll_conf + "\ndo terminal len 0" + "\ndo terminal width 511" + "\ndo sh clock" + "\nobject-group network ipv4 ACL-PYTHON-SCRIPT-TEST\n"


# Checks if the entries in the IP-Block-list.txt are part of the
# ip adress entries in the ENTER_COMPANY_NAME_HERE-public-ip.txt
with open('IP-Block-list.txt') as handleipblock:
	for lineipblock in handleipblock:
		
		
		ipexcp = 0
		refexcp = 0
		
		
		ipblckentry = ipblckentry + 1
		
		
# Strip the whitespaces from each lines
		ipblockntwk = lineipblock.strip()
		ipblockntwk = ipblockntwk.rstrip()


		config_scrpt_log = config_scrpt_log + "\n*******Processing entry no. " + str(ipblckentry) + " from the IP Block address file *******\n"
		print ("\n******* Processing entry no. " + str(ipblckentry) + " from the IP Block address file *******\n")
		

# Start the checks for the ip address block
		try:

# Use the netaddr module to obtain the ipblock network details
			net_ipblockntwk	= IPNetwork(ipblockntwk).network
			ip_ipblockntwk = IPNetwork(ipblockntwk).ip
			nmask_ipblockntwk = IPNetwork(ipblockntwk).netmask
			wldcrdmask_ipblockntwk = IPNetwork(ipblockntwk).hostmask
			prfxlen_ipblockntwk = IPNetwork(ipblockntwk).prefixlen
			tp_net_ipblockntwk	= str(IPNetwork(ipblockntwk).network) + "/" + str(IPNetwork(ipblockntwk).prefixlen)
			ver_ipblockntwk	= IPAddress(ip_ipblockntwk).version


# Check if the ipblock address is iov4			
			if ver_ipblockntwk == 4:
# Check if the ipblock address has a prefix length \0
				if prfxlen_ipblockntwk != 0:
# Check if the ipblock address is not a default network
					if IPAddress(net_ipblockntwk) != IPAddress(net_dfltntwk):
# Check if the ipblock network is not a part of loopback network
						if IPNetwork(tp_net_ipblockntwk) not in IPNetwork(loopbckntwk):
# Check if the ipblock address is not an invalid ip address
							if ip_ipblockntwk == net_ipblockntwk:
								incr_ipblckcount = incr_ipblckcount + 1
# The variableis used to track if the ipblock address matches multiple ENTER_COMPANY_NAME_HERE reference ip address
								ref_match_count_loop = 0

								
								
								
# Open the ENTER_COMPANY_NAME_HERE reference ip address file 
# for processing the checks of ipblock against the ENTER_COMPANY_NAME_HERE ip addresses 


								viacom_cbs_ref_file = "ENTER_COMPANY_NAME_HERE-public-ip.csv"

								with open (viacom_cbs_ref_file) as viacom_cbs_ref_csvfile:
									# Creating a CSV reader
									viacom_cbs_ref_csvreader = csv.reader(viacom_cbs_ref_csvfile)

								# Skipped the 1st row from the firewall file to skip the headers
									next (viacom_cbs_ref_csvreader)
									
									for row in viacom_cbs_ref_csvreader:
									
								# Saving the vaule of the firewall device name and tripping whitespaces
										viacom_cbs_ref_name = row[0].strip()
										viacom_cbs_ref_name = row[0].rstrip()

								# Saving the vaule of the firewall device name and tripping whitespaces
										viacom_cbs_ref_ntwk = row[1].strip()
										viacom_cbs_ref_ntwk = row[1].rstrip()


										refntwk = viacom_cbs_ref_ntwk

										
# Check if the ip address entry in ENTER_COMPANY_NAME_HERE reference file has an empty line 
										if refntwk != "":
# Check if the ipblock ip address matches more than 1 ip address entry in ENTER_COMPANY_NAME_HERE ipaddress reference file
											if ref_match_count_loop == 0:
# Check if the ipblock address and the reference ip address are the same
												if IPNetwork(ipblockntwk).network == IPNetwork(refntwk).network and IPNetwork(ipblockntwk).prefixlen == IPNetwork(refntwk).prefixlen:
														refexcp = refexcp + 1
														ipexcp = ipexcp + 1
														ref_match_count_loop = ref_match_count_loop + 1

# Increement the problem ip count variable and save the problem ip in the variable														
														prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
														prblm_ip_count = prblm_ip_count + 1
# Update the config script log vriable															
														config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n IP address: " + str(ipblockntwk) + " is same as the ENTER_COMPANY_NAME_HERE reference ip address in the reference file " + str(refntwk) + "\n\n"
														print ("\n ATTENTION!! \n IP address: " + str(ipblockntwk) + " is same as the ENTER_COMPANY_NAME_HERE reference ip address in the reference file " + str(refntwk) + "\n\n")
																									
												else:
# Check if the ipblock address is subnet of the reference ip address subnet
													if IPNetwork(ipblockntwk) in IPNetwork(refntwk):
														ipexcp = ipexcp + 1
														ref_match_count_loop = ref_match_count_loop + 1
														
														prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
														prblm_ip_count = prblm_ip_count + 1
															
														config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n IP address: " + str(ipblockntwk) + " is part of the ENTER_COMPANY_NAME_HERE reference ip address file " + str(refntwk) + "\n\n"
														print ("\n ATTENTION!! \n IP address: " + str(ipblockntwk) + " is part of the ENTER_COMPANY_NAME_HERE reference ip address file " + str(refntwk) + "\n\n")
# Check if the reference ip address is subnet of the ipblock address subnet
# This check if very important as it will avoid impact
# It ensures the ipblock address does no includes a 
# supernet which cover reference ip addres subnet
													elif IPNetwork(refntwk) in IPNetwork(ipblockntwk):
														refexcp = refexcp + 1
														ref_match_count_loop = ref_match_count_loop + 1
														
														prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
														prblm_ip_count = prblm_ip_count + 1
																											
														config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n You are blocking an IP address subnet: " + str(ipblockntwk) + " which includes the reference ENTER_COMPANY_NAME_HERE public ip address range: " + str(refntwk) + "\n\n"
														print ("\n ATTENTION!! \n You are blocking an IP address subnet: " + str(ipblockntwk) + " which includes the reference ENTER_COMPANY_NAME_HERE public ip address range: " + str(refntwk) + "\n\n")
											else:
												config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n The IP address subnet provided to block: " + str(ipblockntwk) + " has already been matched against 1 of the ip addresses subnet from the reference ENTER_COMPANY_NAME_HERE public ip address range mentioned above. " + "The check for the new entry: " + str(refntwk) + " and subsequent entries from the reference ip address file will not be checked forward!! \n\n"
												print ("\n ATTENTION!! \n The IP address subnet provided to block: " + str(ipblockntwk) + " has already been matched against 1 of the ip addresses subnet from the reference ENTER_COMPANY_NAME_HERE public ip address range mentioned above. " + "The check for the new entry: " + str(refntwk) + " and subsequent entries from the reference ip address file will not be checked forward!! \n\n")
												break
										else:
											config_scrpt_log = config_scrpt_log + " Please correct!! \n There is an emtpy line in the ENTER_COMPANY_NAME_HERE reference ip address file\n"
											print (" Please correct!! \n There is an emtpy line in the ENTER_COMPANY_NAME_HERE reference ip address file\n")
										

# Checks if the exception variable is not set
# and confirms the pblock address is safe to block
# Prepares the config for firewall and router										
									if ipexcp != 0 or refexcp !=0:
										config_scrpt_log = config_scrpt_log + " The ip address in the  block list is NOT safe to block:" + str(ipblockntwk) + "\n"
										print (" The ip address in the  block list is NOT safe to block:" + str(ipblockntwk) + "\n")
									else:
										config_scrpt_log = config_scrpt_log + " The ip address in block list is safe to block: " + str(ipblockntwk)
										print (" The ip address in block list is safe to block: " + str(ipblockntwk))
# Prepares config for devices for ipblock address mask /32
										if prfxlen_ipblockntwk == 32:
											fw_imp_conf = fw_imp_conf + " network-object host" + " " + str(net_ipblockntwk) + "\n"
											fw_roll_conf = fw_roll_conf + " no network-object host" + " " + str(net_ipblockntwk) + "\n"
											
											rtr_xe_imp_conf = rtr_xe_imp_conf + " " + str(incr_ipblckcount) + " deny ip host " + str(net_ipblockntwk) + " any\n"
											rtr_xe_roll_conf = rtr_xe_roll_conf + " no " + str(incr_ipblckcount) + " deny ip host " + str(net_ipblockntwk) + " any\n"
											
											rtr_xr_imp_conf = rtr_xr_imp_conf + " host" + " " + str(net_ipblockntwk) + "\n"
											rtr_xr_roll_conf = rtr_xr_roll_conf + " no host" + " " + str(net_ipblockntwk) + "\n"

# Prepares config for devices for ipblock address other than mask /32											
										else:
											fw_imp_conf = fw_imp_conf + " network-object" + " " + str(net_ipblockntwk) + " " + str(nmask_ipblockntwk) + "\n"
											fw_roll_conf = fw_roll_conf + " no network-object" + " " + str(net_ipblockntwk) + " " + str(nmask_ipblockntwk) + "\n"
											
											rtr_xe_imp_conf = rtr_xe_imp_conf +  " " + str(incr_ipblckcount) + " deny ip " + str(net_ipblockntwk) + " " + str(wldcrdmask_ipblockntwk) + " any\n"
											rtr_xe_roll_conf = rtr_xe_roll_conf + " no " + str(incr_ipblckcount) + " deny ip " + str(net_ipblockntwk) + " " + str(wldcrdmask_ipblockntwk) + " any\n"

											rtr_xr_imp_conf = rtr_xr_imp_conf + " " + str(net_ipblockntwk) + "/" + str(prfxlen_ipblockntwk) + "\n"
											rtr_xr_roll_conf = rtr_xr_roll_conf + " no " + str(net_ipblockntwk) +  "/" + str(prfxlen_ipblockntwk) + "\n"
		
							else:
								prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
								prblm_ip_count = prblm_ip_count + 1
								
								config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n Please correct the IP address entry in the IP Block file: " + str(ipblockntwk) + "\n" + " The entry is not a subnet or a host ip address.\n"
								print ("\n ATTENTION!! \n Please correct the IP address entry in the IP Block file: " + str(ipblockntwk) + "\n" + " The entry is not a subnet or a host ip address.\n")
						else:
							prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
							prblm_ip_count = prblm_ip_count + 1
							
							config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n The IP address: " + str(net_ipblockntwk) + "/" + str(prfxlen_ipblockntwk) + " is part of the Loopback network " + str(loopbckntwk) + "\n"
							print ("\n ATTENTION!! \n The IP address: " + str(net_ipblockntwk) + "/" + str(prfxlen_ipblockntwk) + " is part of the Loopback network " + str(loopbckntwk) + "\n")
					else:
						prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
						prblm_ip_count = prblm_ip_count + 1
						
						config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n You are blocking a Default subnet 0.0.0.0/0 which may cause OUTAGE: " + str(ip_ipblockntwk) + "/" + str(prfxlen_ipblockntwk) + "\n"
						print ("\n ATTENTION!! \n You are blocking a Default subnet 0.0.0.0/0 which may cause OUTAGE: " + str(ip_ipblockntwk) + "/" + str(prfxlen_ipblockntwk) + "\n")
				else:
					prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
					prblm_ip_count = prblm_ip_count + 1
					
					config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n The IP address with prefix value /0 is not allowed: " + str(net_ipblockntwk) + "/" + str(prfxlen_ipblockntwk) + "\n"
					print ("\n ATTENTION!! \n The IP address with prefix value /0 is not allowed: " + str(net_ipblockntwk) + "/" + str(prfxlen_ipblockntwk) + "\n")
			else:
				prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
				prblm_ip_count = prblm_ip_count + 1
				
				config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n The IP address is not an IPv4 address: " + str(ipblockntwk) + "\nPlease correct and resubmit\n"
				print("\n ATTENTION!! \n The IP address is not an IPv4 address: " + str(ipblockntwk) + "\n Please correct and resubmit\n")

# Except block will run if any of the above check fails 
# and the ip address config will not be generated
		except:
			if ipblockntwk == "":
				config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n There is no IP address in the line. BLANK LINE \n"
				print ("\n ATTENTION!! \n There is no IP address in the line. BLANK LINE \n")
			else:
				prblm_ip_ipblock = prblm_ip_ipblock + ipblockntwk + "\n"
				prblm_ip_count = prblm_ip_count + 1
				
				config_scrpt_log = config_scrpt_log + "\n ATTENTION!! \n The IP address is not a Valid ip address: " + str(ipblockntwk) + "\n Please correct and resubmit\n"
				print("\n ATTENTION!! \n The IP address is not a Valid ip address: " + str(ipblockntwk) + "\n Please correct and resubmit\n")
			pass

# Update the firewall and router config variables		
fw_imp_conf = fw_imp_conf + "wr mem \n exit \n exit \n"
fw_roll_conf = fw_roll_conf + "wr mem \n exit \n exit \n"

rtr_xe_imp_conf = rtr_xe_imp_conf + "do wr mem \n exit \n exit \n"		
rtr_xe_roll_conf = rtr_xe_roll_conf + "do wr mem \n exit \n exit \n"	

rtr_xr_imp_conf = rtr_xr_imp_conf + "\n exit \n commit \n exit \n exit \n"		
rtr_xr_roll_conf = rtr_xr_roll_conf + "\n exit \n commit \n exit \n exit \n"


# Print the firewall and router implementation and rollback config
print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n******* Output of the firewall implementation config variable *******\n")
print(fw_imp_conf)
print("\n******************************************************\n")


print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n******* Output of the firewall rollback config variable *******\n")
print(fw_roll_conf)
print("\n******************************************************\n")


print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n******* Output of the Cisco ISO-XE router implementation config variable *******\n")
print(rtr_xe_imp_conf)
print("\n******************************************************\n")


print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n******* Output of the Cisco ISO-XE router rollback config variable *******\n")
print(rtr_xe_roll_conf)
print("\n******************************************************\n")


print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n******* Output of the Cisco ISO-XR router implementation config variable *******\n")
print(rtr_xr_imp_conf)
print("\n******************************************************\n")


print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n")
print("\n******* Output of the Cisco ISO-XR router rollback config variable *******\n")
print(rtr_xr_roll_conf)
print("\n******************************************************\n")



# Update the problem ip block variable to display the 
# problematic ip addresses
prblm_ip_ipblock = prblm_ip_ipblock + "\n"

print("\n******************************************************")
print("The list of Problematic ip adresses is provided below:")
print("Total problematic ip addresses are: " + str(prblm_ip_count))
print("from a list of total: " + str(ipblckcount) + " ip addresses provided to block")
print("******************************************************\n")
print(prblm_ip_ipblock)

config_scrpt_log = config_scrpt_log + "\n******************************************************"
config_scrpt_log = config_scrpt_log + "\nThe list of Problematic ip adresses is provided below:"
config_scrpt_log = config_scrpt_log + "\nTotal problematic ip addresses are: " + str(prblm_ip_count)
config_scrpt_log = config_scrpt_log + "\nfrom a list of total: " + str(ipblckcount) + " ip addresses provided to block"
config_scrpt_log = config_scrpt_log + "\n******************************************************\n"
config_scrpt_log = config_scrpt_log + str(prblm_ip_ipblock)


# Update the configuration script end time
config_end_time = datetime.now() 
config_total_time = config_end_time - config_start_time


print("\n\n***************************************************************")
print("Config Script Start time for Cisco IOS-XR routers: " + str(config_start_time)) 
print("Config Script End time for Cisco IOS-XR routers: " + str(config_end_time)) 
print("Total time Config script took to prepare implementation and rollback config of ASA, IOS-XE and IOS-XR routers: " + str(config_total_time))
print("***************************************************************\n\n")
config_scrpt_log = config_scrpt_log + "\n\n***************************************************************"
config_scrpt_log = config_scrpt_log + "\nConfig Script Start time for Cisco IOS-XR routers: " + str(config_start_time)
config_scrpt_log = config_scrpt_log + "\nConfig Script End time for Cisco IOS-XR routers: " + str(config_end_time)
config_scrpt_log = config_scrpt_log + "\nTotal time Config script took to prepare implementation and rollback config of ASA, IOS-XE and IOS-XR routers: " + str(config_total_time)
config_scrpt_log = config_scrpt_log + "\n***************************************************************\n\n"


config_datestr = time.strftime("_%d_%m_%Y")


# Copy the firewall implementation config to the file
outfile_fw_imp_conf = open("firewall-imp-config" + str(config_datestr) + ".txt", "w")
outfile_fw_imp_conf.write(fw_imp_conf)

# Copy the firewall rollback config to the file
outfile_fw_roll_conf = open("firewall-roll-config" + str(config_datestr) + ".txt", "w")
outfile_fw_roll_conf.write(fw_roll_conf)

# Copy the Cisco ISO-XE router implementation config to the file
outfile_rtr_xe_imp_conf = open("router-xe-imp-config" + str(config_datestr) + ".txt", "w")
outfile_rtr_xe_imp_conf.write(rtr_xe_imp_conf)

# Copy the Cisco ISO-XE router rollback config to the file
outfile_rtr_xe_roll_conf = open("router-xe-roll-config" + str(config_datestr) + ".txt", "w")
outfile_rtr_xe_roll_conf.write(rtr_xe_roll_conf)

# Copy the Cisco ISO-XR router implementation config to the file
outfile_rtr_xr_imp_conf = open("router-xr-imp-config" + str(config_datestr) + ".txt", "w")
outfile_rtr_xr_imp_conf.write(rtr_xr_imp_conf)

# Copy the Cisco ISO-XR router rollback config to the file
outfile_rtr_xr_roll_conf = open("router-xr-roll-config" + str(config_datestr) + ".txt", "w")
outfile_rtr_xr_roll_conf.write(rtr_xr_roll_conf)

# Copy the script Logs to the file
outfile_config_script_logs = open("config-script-logs" + str(config_datestr) + ".txt", "a")
outfile_config_script_logs.write(config_scrpt_log)

# Close all the files opened for saving the firewall and router
# implementation and the rollback configuration and the script log file
outfile_fw_imp_conf.close()
outfile_fw_roll_conf.close()
outfile_rtr_xe_imp_conf.close()
outfile_rtr_xe_roll_conf.close()
outfile_rtr_xr_imp_conf.close()
outfile_rtr_xr_roll_conf.close()
outfile_config_script_logs.close()




# If there are ip addresses to block in the IP Block file then proceed
# No need to run the script to execute the confg on the devices 
# if the ip addreses to bock are equal to the problematic ip address count

if ipblckcount > 0:


# If the problem ip addresses are less than provided ip addresses in 
# the IP block file then proceed
# Problem ip address count will always be less than the provided ip block 
# address count. If it is higher than there is something wrong with the script


	if prblm_ip_count < ipblckcount:
		# **********************************************************************
		# Block to execute the firewall config on the 
		# firewall list 
		# **********************************************************************
			


		ssh_fw_file = "SSH-firewall-ip.csv"

		with open (ssh_fw_file) as ssh_fw_csvfile:
			# Creating a CSV reader
			ssh_fw_csvreader = csv.reader(ssh_fw_csvfile)

		# Skipped the 1st row from the firewall file to skip the headers
			next (ssh_fw_csvreader)
			
			for row in ssh_fw_csvreader:
			
		# Saving the vaule of the firewall device name and tripping whitespaces
				ssh_fw_name = row[0].strip()
				ssh_fw_name = row[0].rstrip()

		# Saving the vaule of the firewall device name and tripping whitespaces
				ssh_fw_ip = row[1].strip()
				ssh_fw_ip = row[1].rstrip()
						
			
			
			
				# Define the ASA firewall paramaters
				asa_cisco = {
					'device_type': 'cisco_asa',
					'ip': str(ssh_fw_ip),
					'username': 'ENTER_USERNAME_HERE',
					'password': 'ENTER_PASSWORD_HERE',
					'secret': 'ENTER_PASSWORD_HERE',
					'port': '22',
					'verbose': 'True',
					"global_delay_factor": 4
				}
				
				
				# Printing to the log variable to keep output of commands easy to read
				print ("\n====================================================")
				exec_fw_scrpt_log = exec_fw_scrpt_log + ("\n====================================================")
				print ("====================================================")
				exec_fw_scrpt_log = exec_fw_scrpt_log + ("\n====================================================")
				
				print (" Output for device: " + str(ssh_fw_name))
				exec_fw_scrpt_log = exec_fw_scrpt_log + "\n Output for device: " + str(ssh_fw_name)
				
				print ("====================================================")
				exec_fw_scrpt_log = exec_fw_scrpt_log + "\n===================================================="
				print ("====================================================\n")
				exec_fw_scrpt_log = exec_fw_scrpt_log + "\n====================================================\n"

			# If the connect handler fails then execute the exception block of commands	
				try:
					# Define the connection handler for the device
					net_connect = ConnectHandler(**asa_cisco)
					#net_connect.find_prompt()


			# If the command execution fails then execute the exception block of commands			
					try:
						net_connect.enable()
						
						# Send the copy of all the commands in cmd list 
						# to the config_commands list
						#exec_fw_scrpt_log = exec_fw_scrpt_log + net_connect.send_config_set(fw_imp_conf, delay_factor=2, cmd_verify=False)
						exec_fw_eachrun = net_connect.send_config_set(fw_imp_conf, delay_factor=5, cmd_verify=False)
						exec_fw_scrpt_log = exec_fw_scrpt_log + exec_fw_eachrun
					
					except:
						print ("\n The script connected to the ASA firewall but could not execute the commands due to some exception.")
						print ("Please check the commands supplied")
						prblm_fw = prblm_fw + str(ssh_fw_name) + "\n"
						prblm_fw_count = prblm_fw_count + 1
						pass
					
					print (exec_fw_eachrun)
					
					
					# Close the ssh session of the device
					net_connect.disconnect()
					
				except KeyboardInterrupt:
					print ("\n The script was interrupted manually from keyboard to break the command execution on the Cisco ASA Firewall.\n Please check why it was interrupted.\n")
					prblm_fw = prblm_fw + str(ssh_fw_name) + "\n"
					prblm_fw_count = prblm_fw_count + 1
					pass
					
				except:
					print ("\n The script could not connect to the Cisco ASA firewall: " + str(ssh_fw_name) + " via SSH with ip address: " + str(ssh_fw_ip) + "\n Please check the ip address of the device.\n")
					prblm_fw = prblm_fw + str(ssh_fw_name) + "\n"
					prblm_fw_count = prblm_fw_count + 1
					pass
					

			
		exec_fw_scrpt_log = exec_fw_scrpt_log + "\n"
		print("\n")	
		#print (exec_fw_scrpt_log)
		print("\n")



		fw_end_time = datetime.now() 
		fw_total_time = fw_end_time - fw_start_time


		print("\n\n***************************************************************")
		print("Script Start time for Cisco ASA Firewalls: " + str(fw_start_time)) 
		print("Script End time for Cisco ASA Firewalls: " + str(fw_end_time)) 
		print("Total time script ran for Cisco ASA Firewalls: " + str(fw_total_time))
		print("***************************************************************\n\n")
		exec_fw_scrpt_log = exec_fw_scrpt_log + "\n\n***************************************************************"
		exec_fw_scrpt_log = exec_fw_scrpt_log + "\nScript Start time for Cisco ASA Firewalls: " + str(fw_start_time)
		exec_fw_scrpt_log = exec_fw_scrpt_log + "\nScript End time for Cisco ASA Firewalls: " + str(fw_end_time)
		exec_fw_scrpt_log = exec_fw_scrpt_log + "\nTotal time script ran for Cisco ASA Firewalls: " + str(fw_total_time)
		exec_fw_scrpt_log = exec_fw_scrpt_log + "\n***************************************************************\n\n"


		fw_datestr = time.strftime("_%d_%m_%Y")


		# Copy the firewall execute script Logs to the file
		outfile_exec_fw_script_logs = open("exec-fw-script-logs" + str(fw_datestr) + ".txt", "w")
		outfile_exec_fw_script_logs.write(exec_fw_scrpt_log)


		# Close all the files opened for saving the exec log file
		# and the SSH Firewall device list file
		outfile_exec_fw_script_logs.close()





		# **********************************************************************
		# Block to execute the router IOS-XE config on the 
		# IOS-XE router list 
		# **********************************************************************


		ssh_ios_xe_rtr_file = "SSH-router-xe-ip.csv"

		with open (ssh_ios_xe_rtr_file) as ssh_ios_xe_rtr_csvfile:
			# Creating a CSV reader
			ssh_ios_xe_rtr_csvreader = csv.reader(ssh_ios_xe_rtr_csvfile)

		# Skipped the 1st row from the ios-xe router file to skip the headers
			next (ssh_ios_xe_rtr_csvreader)
			
			for row in ssh_ios_xe_rtr_csvreader:
			
		# Saving the vaule of the ios-xe router device name and tripping whitespaces
				ssh_ios_xe_rtr_name = row[0].strip()
				ssh_ios_xe_rtr_name = row[0].rstrip()

		# Saving the vaule of the ios-xe router device name and tripping whitespaces
				ssh_ios_xe_rtr_ip = row[1].strip()
				ssh_ios_xe_rtr_ip = row[1].rstrip()
						
			
				# Define the Cisco Internet router paramaters
				rtr_cisco = {
					'device_type': 'cisco_xe',
					'ip': str(ssh_ios_xe_rtr_ip),
					'username': 'ENTER_USERNAME_HERE',
					'password': 'ENTER_PASSWORD_HERE',
					'secret': 'ENTER_PASSWORD_HERE',
					'port': '22',
					'verbose': 'True',
				}
				
				
				# Printing to the log variable to keep output of commands easy to read
				print ("\n====================================================")
				exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + ("\n====================================================")
				print ("====================================================")
				exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + ("\n====================================================")
				
				print (" Output for device: " + str(ssh_ios_xe_rtr_name))
				exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\n Output for device: " + str(ssh_ios_xe_rtr_name)
				
				print ("====================================================")
				exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\n===================================================="
				print ("====================================================\n")
				exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\n====================================================\n"


			# If the connect handler fails then execute the exception block of commands		
				try:
					# Define the connection handler for the device
					net_connect = ConnectHandler(**rtr_cisco)
					#net_connect.find_prompt()


			# If the command execution fails then execute the exception block of commands					
					try:
						net_connect.enable()
						
						# Send the copy of all the commands in cmd list 
						# to the config_commands list
						#exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + net_connect.send_config_set(rtr_xe_imp_conf, cmd_verify=False)
						exec_rtr_xe_eachrun = net_connect.send_config_set(rtr_xe_imp_conf, delay_factor=5, cmd_verify=False)
						exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + exec_rtr_xe_eachrun
					
					except:
						print ("\n The script connected to the Ciscon IOS-XE router but could not execute the commands due to some exception.")
						print ("Please check the commands supplied")
						prblm_rtr = prblm_rtr + str(ssh_ios_xe_rtr_name) + "\n"
						prblm_rtr_count = prblm_rtr_count + 1
						pass
					
					print (exec_rtr_xe_eachrun)
					
					# Close the ssh session of the device
					net_connect.disconnect()
					
				except KeyboardInterrupt:
					print ("\n The script was interrupted manually from keyboard to break the command execution on the Cisco IOS_XE router.\n Please check why it was interrupted.\n")	
					prblm_rtr = prblm_rtr + str(ssh_ios_xe_rtr_name) + "\n"
					prblm_rtr_count = prblm_rtr_count + 1
					pass
					
				except:
					print ("\n The script could not connect to the Cisco IOS_XE router: " + str(ssh_ios_xe_rtr_name) + " via SSH with ip address: " + str(ssh_ios_xe_rtr_ip) + "\n Please check the ip address of the device.\n")
					prblm_rtr = prblm_rtr + str(ssh_ios_xe_rtr_name) + "\n"
					prblm_rtr_count = prblm_rtr_count + 1
					pass
				
			
		exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\n"
		print("\n")	
		#print (exec_rtr_xe_scrpt_log)
		print("\n")



		rtr_xe_end_time = datetime.now() 
		rtr_xe_total_time = rtr_xe_end_time - rtr_xe_start_time


		print("\n\n***************************************************************")
		print("Script Start time for Cisco IOS-XE routers: " + str(rtr_xe_start_time)) 
		print("Script End time for Cisco IOS-XE routers: " + str(rtr_xe_end_time)) 
		print("Total time script ran for Cisco IOS-XE routers: " + str(rtr_xe_total_time))
		print("***************************************************************\n\n")
		exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\n\n***************************************************************"
		exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\nScript Start time for Cisco IOS-XE routers: " + str(rtr_xe_start_time)
		exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\nScript End time for Cisco IOS-XE routers: " + str(rtr_xe_end_time)
		exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\nTotal time script ran for Cisco IOS-XE routers: " + str(rtr_xe_total_time)
		exec_rtr_xe_scrpt_log = exec_rtr_xe_scrpt_log + "\n***************************************************************\n\n"


		rtr_xe_datestr = time.strftime("_%d_%m_%Y")


		# Copy the Ciscon router IOS-XE execute script Logs to the file
		outfile_exec_rtr_xe_script_logs = open("exec-rtr-xe-script-logs" + str(rtr_xe_datestr) + ".txt", "w")
		outfile_exec_rtr_xe_script_logs.write(exec_rtr_xe_scrpt_log)


		# Close all the files opened for saving the exec log file
		outfile_exec_rtr_xe_script_logs.close()






		# **********************************************************************
		# Block to execute the router IOS-XR config on the 
		# IOS-XR router list 
		# **********************************************************************



		ssh_ios_xr_rtr_file = "SSH-router-xr-ip.csv"

		with open (ssh_ios_xr_rtr_file) as ssh_ios_xr_rtr_csvfile:
			# Creating a CSV reader
			ssh_ios_xr_rtr_csvreader = csv.reader(ssh_ios_xr_rtr_csvfile)

		# Skipped the 1st row from the ios-xr router file to skip the headers
			next (ssh_ios_xr_rtr_csvreader)
			
			for row in ssh_ios_xr_rtr_csvreader:
			
		# Saving the vaule of the ios-xr router device name and tripping whitespaces
				ssh_ios_xr_rtr_name = row[0].strip()
				ssh_ios_xr_rtr_name = row[0].rstrip()

		# Saving the vaule of the ios-xr router device name and tripping whitespaces
				ssh_ios_xr_rtr_ip = row[1].strip()
				ssh_ios_xr_rtr_ip = row[1].rstrip()
			
				
				# Define the Cisco Internet router paramaters
				rtr_xr_cisco = {
					'device_type': 'cisco_xr',
					'ip': str(ssh_ios_xr_rtr_ip),
					'username': 'ENTER_USERNAME_HERE',
					'password': 'ENTER_PASSWORD_HERE',
					'secret': 'ENTER_PASSWORD_HERE',
					'port': '22',
					'verbose': 'True',
				}
				
				
				# Printing to the log variable to keep output of commands easy to read
				print ("\n====================================================")
				exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + ("\n====================================================")
				print ("====================================================")
				exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + ("\n====================================================")
				
				print (" Output for device: " + str(ssh_ios_xr_rtr_name))
				exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\n Output for device: " + str(ssh_ios_xr_rtr_name)
				
				print ("====================================================")
				exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\n===================================================="
				print ("====================================================\n")
				exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\n====================================================\n"


			# If the connect handler fails then execute the exception block of commands		
				try:
					# Define the connection handler for the device
					net_connect = ConnectHandler(**rtr_xr_cisco)
					#net_connect.find_prompt()


			# If the command execution fails then execute the exception block of commands					
					try:
						net_connect.enable()
						
						# Send the copy of all the commands in cmd list 
						# to the config_commands list
						#exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + net_connect.send_config_set(rtr_xr_imp_conf, cmd_verify=False)
						exec_rtr_xr_eachrun = net_connect.send_config_set(rtr_xr_imp_conf, delay_factor=5, cmd_verify=False)
						exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + exec_rtr_xr_eachrun
					
					except:
						print ("\n The script connected to the Cisco IOS-XR Router but could not execute the commands due to some exception.")
						print ("Please check the commands supplied")
						prblm_rtr = prblm_rtr + str(ssh_ios_xr_rtr_name) + "\n"
						prblm_rtr_count = prblm_rtr_count + 1
						pass
					
					print (exec_rtr_xr_eachrun)
					
					# Close the ssh session of the device
					net_connect.disconnect()
					
				except KeyboardInterrupt:
					print ("\n The script was interrupted manually from keyboard to break the command execution on the Cisco IOS_XR router.\n Please check why it was interrupted.\n")	
					prblm_rtr = prblm_rtr + str(ssh_ios_xr_rtr_name) + "\n"
					prblm_rtr_count = prblm_rtr_count + 1
					pass
					
				except:
					print ("\n The script could not connect to the Cisco IOS_XR router: " + str(ssh_ios_xr_rtr_name) + "via SSH with ip address: " + str(ssh_ios_xr_rtr_ip) + "\n Please check the ip address of the device.\n")
					prblm_rtr = prblm_rtr + str(ssh_ios_xr_rtr_name) + "\n"
					prblm_rtr_count = prblm_rtr_count + 1
					pass
				
			
		exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\n"
		print("\n")	
		#print (exec_rtr_xr_scrpt_log)
		print("\n")



		rtr_xr_end_time = datetime.now() 
		rtr_xr_total_time = rtr_xr_end_time - rtr_xr_start_time


		print("\n\n***************************************************************")
		print("Script Start time for Cisco IOS-XR routers: " + str(rtr_xr_start_time)) 
		print("Script End time for Cisco IOS-XR routers: " + str(rtr_xr_end_time)) 
		print("Total time script ran for Cisco IOS-XR routers: " + str(rtr_xr_total_time))
		print("***************************************************************\n\n")
		exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\n\n***************************************************************"
		exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\nScript Start time for Cisco IOS-XR routers: " + str(rtr_xr_start_time)
		exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\nScript End time for Cisco IOS-XR routers: " + str(rtr_xr_end_time)
		exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\nTotal time script ran for Cisco IOS-XR routers: " + str(rtr_xr_total_time)
		exec_rtr_xr_scrpt_log = exec_rtr_xr_scrpt_log + "\n***************************************************************\n\n"


		rtr_xr_datestr = time.strftime("_%d_%m_%Y")


		# Copy the Cisco router IOS-XR execute script Logs to the file
		outfile_exec_rtr_xr_script_logs = open("exec-rtr-xr-script-logs" + str(rtr_xr_datestr) + ".txt", "w")
		outfile_exec_rtr_xr_script_logs.write(exec_rtr_xr_scrpt_log)


		# Close all the files opened for saving the exec log file
		outfile_exec_rtr_xr_script_logs.close()


		# Summarisation of devices on which the script failed to execute
		print("\n\n***************************************************************")
		print("The ip block was not performed on below firewalls: ") 
		print("***************************************************************\n\n")
		print(prblm_fw)

		print("\n\n***************************************************************")
		print("The ip block was not performed on below routers: ")
		print("***************************************************************\n\n")
		print (prblm_rtr)


		# Summarisation of problematic ip addresses in the ip block file
		prblm_ip_ipblock = prblm_ip_ipblock + "\n"

		print("\n******************************************************")
		print("The list of Problematic ip adresses is provided below:")
		print("Total problematic ip addresses are: " + str(prblm_ip_count))
		print("from a list of total: " + str(ipblckcount) + " ip addresses provided to block")
		print("******************************************************\n")
		print(prblm_ip_ipblock)



		# **********************************************************************
		# Block to copy the files created to the 
		# London FTP server 
		# **********************************************************************


			
		ftp_srvr = ftplib.FTP()
		ftp_srvr.set_debuglevel(2)
		ftp_srvr.connect(ftp_lon_srvr_ip, ftp_lon_srvr_port)
		print (ftp_srvr.getwelcome())

		# Copying the contents of the IPblock file to another IPblock_todaydate file
		old_ipblock_file=open('IP-Block-list.txt')  
		new_ipblock_file=open('IP-Block-list' + str(config_datestr) + ".txt",'a')
		for x in old_ipblock_file.readlines():
			new_ipblock_file.write(x)
		old_ipblock_file.close()
		new_ipblock_file.close()


		# If the FTP login fails then execute the exception block of commands
		# else execute the block of commands in the else block	
		try:
			print ("\nLogging in to the FTP server...")
			ftp_srvr.login(ftp_lon_srvr_user, ftp_lon_srvr_password)
		except:
			print ("\n FTP login failed.")
		else:	

			# Assigning name of the old ip block file to the variable
			outfile_old_ipblock = "IP-Block-list.txt" 

			# Create the new ip block file variable to copy to FTP server
			outfile_new_ipblock = "IP-Block-list" + str(config_datestr) + ".txt"
			
			# Copy the firewall implementation config to the FTP Server
			outfile_fw_imp_conf = "firewall-imp-config" + str(config_datestr) + ".txt"

			# Copy the firewall rollback config to the FTP Server
			outfile_fw_roll_conf = "firewall-roll-config" + str(config_datestr) + ".txt"

			# Copy the Cisco ISO-XE router implementation config to the FTP Server
			outfile_rtr_xe_imp_conf = "router-xe-imp-config" + str(config_datestr) + ".txt"

			# Copy the Cisco ISO-XE router rollback config to the FTP Server
			outfile_rtr_xe_roll_conf = "router-xe-roll-config" + str(config_datestr) + ".txt"

			# Copy the Cisco ISO-XR router implementation config to the FTP Server
			outfile_rtr_xr_imp_conf = "router-xr-imp-config" + str(config_datestr) + ".txt"

			# Copy the Cisco ISO-XR router rollback config to the FTP Server
			outfile_rtr_xr_roll_conf = "router-xr-roll-config" + str(config_datestr) + ".txt"

			# Copy the script Logs to the FTP Server
			outfile_config_script_logs = "config-script-logs" + str(config_datestr) + ".txt"

			# Copy the firewall execute script Logs to the file
			outfile_exec_fw_script_logs = "exec-fw-script-logs" + str(fw_datestr) + ".txt"
			
			# Copy the Cisco router IOS-XE execute script Logs to the file
			outfile_exec_rtr_xe_script_logs = "exec-rtr-xe-script-logs" + str(rtr_xe_datestr) + ".txt"
			
			# Copy the Cisco router IOS-XR execute script Logs to the file
			outfile_exec_rtr_xr_script_logs = "exec-rtr-xr-script-logs" + str(rtr_xr_datestr) + ".txt"
			
			ftp_srvr.storbinary('STOR ' + outfile_new_ipblock, open(outfile_new_ipblock, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_fw_imp_conf, open(outfile_fw_imp_conf, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_fw_roll_conf, open(outfile_fw_roll_conf, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_rtr_xe_imp_conf, open(outfile_rtr_xe_imp_conf, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_rtr_xe_roll_conf, open(outfile_rtr_xe_roll_conf, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_rtr_xr_imp_conf, open(outfile_rtr_xr_imp_conf, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_rtr_xr_roll_conf, open(outfile_rtr_xr_roll_conf, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_config_script_logs, open(outfile_config_script_logs, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_exec_fw_script_logs, open(outfile_exec_fw_script_logs, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_exec_rtr_xe_script_logs, open(outfile_exec_rtr_xe_script_logs, 'rb'))
			ftp_srvr.storbinary('STOR ' + outfile_exec_rtr_xr_script_logs, open(outfile_exec_rtr_xr_script_logs, 'rb'))
			ftp_srvr.storbinary('STOR ' + log_filename, open(log_filename, 'rb'))

			
			# Close the FTP server connection	
			ftp_srvr.quit()
			ftp_srvr.close()



		# **********************************************************************
		# Block to send email of all script successful run  
		# to the email recipients 
		# **********************************************************************

			
		# SMTP server cariable definition
		port = 25
		smtp_server = "ENTER_EMAIL_SERVER_HERE"
		login = "ENTER_SMTP_USERNAME_HERE" 
		password = "ENTER_SMTP_PASSWORD_HERE"


		# specify the sender’s and receiver’s email addresses
		sender = "ENTER_SENDER_EMAIL_ADDRESS_HERE"
		receiver = "ENTER_RECEIVER_EMAIL_ADDRESS_HERE"

		# type your message: use two newlines (\n) to separate the subject from the message body, and use 'f' to  automatically insert variables in the text

		if prblm_rtr_count == 0 and prblm_fw_count == 0:
			message = """
			Subject: Python automation script Status
			To: """+str(receiver)+"""
			From: """+str(sender)+"""

			The script ran successfully on all the firewalls and routers. 

			
			******************************************************
			The list of Problematic ip adresses is provided below:
			Total problematic ip addresses are: """+str(prblm_ip_count)+"""

			from a list of total: """+str(ipblckcount)+""" ip address block
			******************************************************

			"""+"\n"+str(prblm_ip_ipblock)+""" 

			"""
		else:
			message = """
			Subject: Python automation script Status """+str(config_datestr)+"""
			To: """+str(receiver)+"""
			From: """+str(sender)+"""

			The script did not run successfully on all the firewalls and routers.


			***************************************************************
			The ip block was not performed on below firewalls:
			***************************************************************
			"""+"\n"+str(prblm_fw)+"""

			***************************************************************
			The ip block was not performed on below routers:
			***************************************************************
			"""+"\n"+str(prblm_rtr)+"""


			******************************************************
			The list of Problematic ip adresses is provided below:
			Total problematic ip addresses are: """+str(prblm_ip_count)+"""

			from a list of total: """+str(ipblckcount)+""" ip address block
			******************************************************

			"""+"\n"+str(prblm_ip_ipblock)+""" 

			"""
			
		# print(message)	

		try:
			# send your message with credentials specified above
			with smtplib.SMTP(smtp_server, port) as server:
				server.login(login, password)
				server.sendmail(sender, receiver, message.encode('utf8'))
			#print(message)

			# tell the script to report if your message was sent or which errors need to be fixed 
			print('The script ran succesfully and the Email was sent')
		except (gaierror, ConnectionRefusedError):
			print('Failed to connect to the server. Bad connection settings?')
		except smtplib.SMTPServerDisconnected:
			print('Failed to connect to the server. Wrong user/password?')
		except smtplib.SMTPException as e:
			print('SMTP error occurred: ' + str(e))
			

		# **********************************************************************
		# Delete all the files used for saving the firewall and router
		# implementation and the rollback configuration and the script log file
		# **********************************************************************


		try:	

			os.remove(outfile_fw_imp_conf)
			os.remove(outfile_fw_roll_conf)
			os.remove(outfile_rtr_xe_imp_conf)
			os.remove(outfile_rtr_xe_roll_conf)
			os.remove(outfile_rtr_xr_imp_conf)
			os.remove(outfile_rtr_xr_roll_conf)
			os.remove(outfile_config_script_logs)
			os.remove(outfile_exec_fw_script_logs)
			os.remove(outfile_exec_rtr_xe_script_logs)
			os.remove(outfile_exec_rtr_xr_script_logs)
			os.remove(outfile_old_ipblock)
			os.remove(outfile_new_ipblock)
			print ("\n\nDeleted all the files from the local system")
		except:
			print("\nOne of the files could not be deleted.\n")


		# Recreating the IP block file for reuse
		f = open("IP-Block-list.txt", "a")
		f.close()
		
	else:
		print("\n All the ip addresses provided to block are having issues. \n The configurations will not be executed on the devices.")
		
		# **********************************************************************
		# Block to copy the files created to the 
		# London FTP server 
		# **********************************************************************


			
		ftp_srvr = ftplib.FTP()
		ftp_srvr.set_debuglevel(2)
		ftp_srvr.connect(ftp_lon_srvr_ip, ftp_lon_srvr_port)
		print (ftp_srvr.getwelcome())

		# Copying the contents of the IPblock file to another IPblock_todaydate file
		old_ipblock_file=open('IP-Block-list.txt')  
		new_ipblock_file=open('IP-Block-list' + str(config_datestr) + ".txt",'a')
		for x in old_ipblock_file.readlines():
			new_ipblock_file.write(x)
		old_ipblock_file.close()
		new_ipblock_file.close()


		# If the FTP login fails then execute the exception block of commands
		# else execute the block of commands in the else block	
		try:
			print ("\nLogging in to the FTP server...")
			ftp_srvr.login(ftp_lon_srvr_user, ftp_lon_srvr_password)
		except:
			print ("\n FTP login failed.")
		else:	

			# Assigning name of the old ip block file to the variable
			outfile_old_ipblock = "IP-Block-list.txt" 

			# Create the new ip block file variable to copy to FTP server
			outfile_new_ipblock = "IP-Block-list" + str(config_datestr) + ".txt"
			
			ftp_srvr.storbinary('STOR ' + outfile_new_ipblock, open(outfile_new_ipblock, 'rb'))
			
			
			# Close the FTP server connection	
			ftp_srvr.quit()
			ftp_srvr.close()
	
		
		# **********************************************************************
		# Block to send email of all script successful run  
		# to the email recipients 
		# **********************************************************************

			
		# SMTP server cariable definition
		port = 25
		smtp_server = "ENTER_SMTP_SERVER_HERE"
		login = "ENTER_SMTP_USERNAME_HERE" 
		password = "ENTER_SMTP_PASSWORD_HERE"


		# specify the sender’s and receiver’s email addresses
		sender = "ENTER_SENDER_EMAIL_ADDRESS_HERE"
		receiver = "ENTER_RECEIVER_EMAIL_ADDRESS_HERE"

		# type your message: use two newlines (\n) to separate the subject from the message body, and use 'f' to  automatically insert variables in the text

		message = """
		Subject: Python automation script Status
		To: """+str(receiver)+"""
		From: """+str(sender)+"""

		The script ran successfully but configuration not executed on the firewalls and routers. 
		All the ip addresses provided to block in the IP Block file are not Valid.

		
		******************************************************
		The list of Problematic ip adresses is provided below:
		Total problematic ip addresses are: """+str(prblm_ip_count)+"""

		from a list of total: """+str(ipblckcount)+""" ip address block
		******************************************************

		"""+"\n"+str(prblm_ip_ipblock)+""" 

		"""	
			
		try:
			# send your message with credentials specified above
			with smtplib.SMTP(smtp_server, port) as server:
				server.login(login, password)
				server.sendmail(sender, receiver, message.encode('utf8'))
			#print(message)

			# tell the script to report if your message was sent or which errors need to be fixed 
			print('The script ran successfully but configuration not executed on the firewalls and routers. \nAll the ip addresses provided to block are not Valid')
		except (gaierror, ConnectionRefusedError):
			print('Failed to connect to the server. Bad connection settings?')
		except smtplib.SMTPServerDisconnected:
			print('Failed to connect to the server. Wrong user/password?')
		except smtplib.SMTPException as e:
			print('SMTP error occurred: ' + str(e))	
			
		


		# **********************************************************************
		# Delete the IP BLOCK file and the new IP BLOK file
		# **********************************************************************


		try:	

			os.remove(outfile_old_ipblock)
			os.remove(outfile_new_ipblock)
			print ("\n\nDeleted all the files from the local system")
		except:
			print("\nOne of the files could not be deleted.\n")


		# Recreating the IP block file for reuse
		f = open("IP-Block-list.txt", "a")
		f.close()
		
		
else:
	print("\n There are no Valid ip addresses  to block. \n The configurations will not be executed on the devices.")

	

	# **********************************************************************
	# Block to copy the files created to the 
	# London FTP server 
	# **********************************************************************


			
	ftp_srvr = ftplib.FTP()
	ftp_srvr.set_debuglevel(2)
	ftp_srvr.connect(ftp_lon_srvr_ip, ftp_lon_srvr_port)
	print (ftp_srvr.getwelcome())

	# Copying the contents of the IPblock file to another IPblock_todaydate file
	old_ipblock_file=open('IP-Block-list.txt')  
	new_ipblock_file=open('IP-Block-list' + str(config_datestr) + ".txt",'a')
	for x in old_ipblock_file.readlines():
		new_ipblock_file.write(x)
	old_ipblock_file.close()
	new_ipblock_file.close()


	# If the FTP login fails then execute the exception block of commands
	# else execute the block of commands in the else block	
	try:
		print ("\nLogging in to the FTP server...")
		ftp_srvr.login(ftp_lon_srvr_user, ftp_lon_srvr_password)
	except:
		print ("\n FTP login failed.")
	else:	

		# Assigning name of the old ip block file to the variable
		outfile_old_ipblock = "IP-Block-list.txt" 

		# Create the new ip block file variable to copy to FTP server
		outfile_new_ipblock = "IP-Block-list" + str(config_datestr) + ".txt"
			
		ftp_srvr.storbinary('STOR ' + outfile_new_ipblock, open(outfile_new_ipblock, 'rb'))
			
			
		# Close the FTP server connection	
		ftp_srvr.quit()
		ftp_srvr.close()
	
		
	# **********************************************************************
	# Block to send email of all script successful run  
	# to the email recipients 
	# **********************************************************************

			
	# SMTP server cariable definition
	port = 25
	smtp_server = "ENTER_SMTP_SERVER_HERE"
	login = "ENTER_SMTP_USERNAME_HERE" 
	password = "ENTER_SMTP_PASSWORD_HERE"


	# specify the sender’s and receiver’s email addresses
	sender = "ENTER_SENDER_EMAIL_ADDRESS_HERE"
	receiver = "ENTER_RECEIVER_EMAIL_ADDRESS_HERE"

	# type your message: use two newlines (\n) to separate the subject from the message body, and use 'f' to  automatically insert variables in the text

	message = """
	Subject: Python automation script Status
	To: """+str(receiver)+"""
	From: """+str(sender)+"""

	The script ran successfully but there were no ip addresses in the IP block file.

		
	******************************************************
	The list of Problematic ip adresses is provided below:
	Total problematic ip addresses are: """+str(prblm_ip_count)+"""

	from a list of total: """+str(ipblckcount)+""" ip address block
	******************************************************

	"""+"\n"+str(prblm_ip_ipblock)+""" 

	"""	
			
	try:
		# send your message with credentials specified above
		with smtplib.SMTP(smtp_server, port) as server:
			server.login(login, password)
			server.sendmail(sender, receiver, message.encode('utf8'))
		#print(message)

		# tell the script to report if your message was sent or which errors need to be fixed 
		print('The script ran successfully but configuration not executed on the firewalls and routers. \nAll the ip addresses provided to block are not Valid')
	except (gaierror, ConnectionRefusedError):
		print('Failed to connect to the server. Bad connection settings?')
	except smtplib.SMTPServerDisconnected:
		print('Failed to connect to the server. Wrong user/password?')
	except smtplib.SMTPException as e:
		print('SMTP error occurred: ' + str(e))	
			
		


		# **********************************************************************
		# Delete the IP BLOCK file and the new IP BLOK file
		# **********************************************************************

	try:	

		os.remove(outfile_old_ipblock)
		os.remove(outfile_new_ipblock)
		print ("\n\nDeleted all the files from the local system")
	except:
		print("\nOne of the files could not be deleted.\n")


	# Recreating the IP block file for reuse
	f = open("IP-Block-list.txt", "a")
	f.close()