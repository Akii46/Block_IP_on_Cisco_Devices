# Block_IP_on_Cisco_Devices

# Script Pre-requisites to run:
# 1. Install netmiko and paramiko module 
# 2. Install netaddr module
# 3. Install ipaddr module

The script will let you block ip addresses on the Cisco Routers running IOS-XR, IOS-XE, and ASA firewalls. It can be edited to also include the IOS devices since IOS-XE and IOS have the same command structure. 

The device (router and firewall) IP addresses are provided in the CSV files that act as device inventory to the script. 

The IP addresses to be blocked can be provided in the IP-Block-List.txt file. 

The Company's public IP address ranges that should never get blocked accidentally must be provided in the public IP address CSV file.

The script reads the ip-block-list.txt file and verifies every ip address in the file by running it through different checks and also cross checks it with every single entry on the company'spublic ip address ranges provided int he public ip address csv file. It ensures the ip address provided to block is not a subnet or supernet of the company's public ip address.

It then creates configuration for the devices and saves it to different files that gets pushed to the devices and saved.


