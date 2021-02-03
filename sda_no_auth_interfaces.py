"""
Author: Aninda Chatterjee

The script uses existing DNAC APIs to get a list of all network devices and their configurations. 
It then parses through each device configuration to determine if there are any interfaces that are 
configured for no authentication (essentially lack of a 'source template' command under the interface
as expected with IBNS 2.0 configuration).

The script excludes all LISP, Loopback and L3 ports from this parsing.
"""
import re
import rich
import csv
import requests
import warnings
import getpass
import json
from requests.auth import HTTPBasicAuth

def get_dnac_auth_token(dnac_ip_address, dnac_user, dnac_pass):

    # partial URL defined to concatenate later

    url = '/dna/system/api/v1/auth/token'

    # get DNAC IP address and login details
    # commented out for now - a better approach is to
    # source this in the main function and then pass
    # it into this function

    #dnac_ip_address = input("Enter DNAC IP address: ")
    #dnac_user = input("Enter username for DNAC login: ")
    #dnac_pass = input("Enter password for DNAC login: ")

    # concatenate the DNAC IP address obtained from user
    # with the full string to form the complete URL needed to
    # obtain the token

    full_url = 'https://' + dnac_ip_address + url

    # the post request will throw a warning because certification
    # validation is being disabled with verify=False
    # this displays the warning to the user, so we are filtering it

    warnings.filterwarnings("ignore")

    # post request to retreive token in json format and then store it
    # as a string in a variable called token. Return this variable
    response = requests.post(full_url, auth=HTTPBasicAuth(dnac_user,dnac_pass), headers={"Content-Type": "application/json"}, verify=False)
    token = response.json()["Token"]
    return token

def dnac_get_all_devices(token, dnac_ip_address):
    device_list = []
    url = '/api/v1/network-device'
    full_url = 'https://' + dnac_ip_address + url
    warnings.filterwarnings("ignore")
    response = requests.get(full_url, headers={"Content-Type": "application/json", "X-Auth-Token": token}, verify=False)

    # strip the response to include only the "response"
    # entry from the json dictionary

    stripped_response = response.json()["response"]
    #print(stripped_response)

    for x in stripped_response:
        temp_dict = {}
        temp_dict['hostname'] = x['hostname']
        temp_dict['ip_address'] = x['managementIpAddress']
        temp_dict['id'] = x['id']
        temp_dict['family'] = x['family']
        device_list.append(temp_dict)
    return device_list

def get_device_config(dnac_ip_address, token, device_list):
    """ function to retrieve configuration of a device
    based on device UUID
    """
    headers = {"Content-Type": "application/json", "X-Auth-Token": token, "Accept": "application/json"}
    device_config = []
    url = "/dna/intent/api/v1/network-device/"
    for x in device_list:
        if x['family'] == 'Unified AP' or x['family'] == 'Wireless Controller':
            continue
        temp_dict = {}
        full_url = "https://" + dnac_ip_address + url + x['id'] + "/config"
        config = requests.get(full_url, headers=headers, verify=False)
        temp_dict['hostname'] = x['hostname']
        temp_dict['id'] = x['id']

        # some APIs are potentially broken due to a known bug - CSCvr70208
        # REST API bundle needs to be restarted on the DNAC GUI to fix this
        # try/except block to catch any potential issues with the API

        try:
            temp_dict['config'] = config.json()['response']
            device_config.append(temp_dict)
        except:
            print("API error - please restart REST API bundle on DNAC GUI and try again\n")
            break
    return device_config

def get_all_interfaces_with_no_auth(device_config):
    interface_with_no_auth_list = []
    for device in device_config:
        match_interfaces = re.findall(r"^interface [a-zA-z0-9\/\s_-]+!$", device['config'], re.MULTILINE)
        for interface_config in match_interfaces:
            interface_name_search = re.search(r"interface (?P<intf_name>[a-zA-Z0-9\/]+)", interface_config)
            interface_name = interface_name_search['intf_name']
            if not 'LISP' in interface_name and not 'Vlan' in interface_name and not 'Loopback' in interface_name:
                auth_match = re.search(r"source template (?P<auth_type>\w+)", interface_config)
                ip_address_match = re.search(r"ip address \d+.\d+.\d+.\d+ \d+.\d+.\d+.\d+", interface_config)
                if not auth_match and not ip_address_match:
                    temp_dict = {}
                    temp_dict['hostname'] = device['hostname']
                    temp_dict['intf_name'] = interface_name
                    interface_with_no_auth_list.append(temp_dict)
    return interface_with_no_auth_list

def main():
    # get DNAC IP address and login details

    dnac_ip_address = input("Enter DNAC IP address: ")
    dnac_user = input("Enter username for DNAC login: ")
    dnac_pass = getpass.getpass(prompt="Enter password for DNAC login: ")
    file_path = input("Enter complete file path to save data: ")
    try:
        token  = get_dnac_auth_token(dnac_ip_address, dnac_user, dnac_pass)
    except:
        raise AuthenticationError("Authentication failure. Please check DNAC IP address and login credentials.")

    # get list of all fabric devices first

    device_list = dnac_get_all_devices(token, dnac_ip_address)
    device_config = get_device_config(dnac_ip_address, token, device_list)
    no_auth_interfaces = get_all_interfaces_with_no_auth(device_config)
    try:
        with open(file_path, 'w', encoding='utf-8-sig') as no_auth_intf_file:
            no_auth_file_writer = csv.writer(no_auth_intf_file)

            for interface in no_auth_interfaces:
                no_auth_file_writer.writerow([interface['hostname'], interface['intf_name']])
    except:
        print("Could not open file\n")

if __name__ == '__main__':
    main()
