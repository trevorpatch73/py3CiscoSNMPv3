import csv
import requests
import json
import os
from netmiko import ConnectHandler

# Import authentication credentials to Cisco inventory
username = os.environ.get('CISCO_USERNAME')
password = os.environ.get('CISCO_PASSWORD')
secret = os.environ.get('CISCO_SECRET')

# Define the SNMPv3 configuration
snmp_config = {
    'community': 'public',
    'username': 'snmpuser',
    'auth_protocol': 'sha',
    'auth_password': os.environ.get('SNMPv3_AUTH_PASSWORD'),
    'priv_protocol': 'aes128',
    'priv_bits': '128',
    'priv_password': os.environ.get('SNMPv3_PRIV_PASSWORD'),
}

with open('CISCO-SNMPv3-INVENTORY.csv', 'r') as file:
    reader = csv.DictReader(file)
    for row in reader:
        
        # Get the device details from the CSV file
        device_type = row['DEVICE_TYPE']
        ip = row['IP_ADDRESS']
        
        # Define the device dictionary
        device = {
            'device_type': device_type,
            'ip': ip,
            'username': username,
            'password': password,
            'secret': secret,
        }

        # Define the SNMPv3 commands for each device type
        if device['device_type'] == 'IOS':
            commands = [
                'snmp-server view ViewDefault iso included '
                'snmp-server group {} v3 priv read ViewDefault'.format(snmp_config['community']),
                'snmp-server user {} {} v3 auth {} {} priv {} {} {}'.format(snmp_config['username'], snmp_config['community'], snmp_config['auth_protocol'], snmp_config['auth_password'], snmp_config['priv_protocol'], snmp_config['priv_bits'], snmp_config['priv_password']),
            ]
        elif device['device_type'] == 'NXOS':
            commands = [
                'snmp-server user {} network-admin v3 auth {} {} priv {}-{} {}'.format(snmp_config['username'], snmp_config['auth_protocol'], snmp_config['auth_password'], snmp_config['priv_protocol'], snmp_config['priv_bits'], snmp_config['priv_password']),
            ]
        elif device['device_type'] == 'FXOS':
            commands = [
                'scope monitoring',
                'enable snmp',
                'create snmp-user {}'.format(snmp_config['username']),
                'set auth {}'.format(snmp_config['auth_protocol']),
                'set {}-{} yes'.format(snmp_config['priv_protocol'], snmp_config['priv_bits']),
                'set password',
                '{}'.format(snmp_config['priv_password']),
                'commit-buffer',
            ]
        elif device['device_type'] == 'ASA':
            commands = [
                'snmp-server group {} v3 priv read ViewDefault'.format(snmp_config['community']),
                'snmp-server user {} {} v3 auth {} {} priv {} {} {}'.format(snmp_config['username'], snmp_config['community'], snmp_config['auth_protocol'], snmp_config['auth_password'], snmp_config['priv_protocol'], snmp_config['priv_bits'], snmp_config['priv_password']),
            ]
        elif device['device_type'] == 'ACI':
        
            # Define variables from environmental variables
            apic_url = row['CONTROLLER_IP']
            apic_username = username
            apic_password = password

            # Authenticate and obtain token from APIC
            auth_url = f"{apic_url}/api/aaaLogin.json"
            auth_payload = {
                "aaaUser": {
                    "attributes": {
                        "name": apic_username,
                        "pwd": apic_password
                    }
                }
            }
            auth_headers = {
                "Content-Type": "application/json"
            }
            auth_response = requests.post(auth_url, headers=auth_headers, data=json.dumps(auth_payload), verify=False)

            # Check the API response status code and print the response content
            if auth_response.status_code == 200:
                print("API Authentication successful.")
                auth_token = auth_response.json()['imdata'][0]['aaaLogin']['attributes']['token']
            else:
                print("API Authentication Failure.")
                print(auth_response.content)
                exit(1)

            # Define the JSON payload
            snmp_config = {
                "snmpUser": {
                    "attributes": {
                        "userName": "snmpuser",
                        "authPassword": os.environ.get('AUTH_PASSWORD'),
                        "authType": "{}".format(snmp_config['auth_protocol']),
                        "privPassword": os.environ.get('PRIV_PASSWORD'),
                        "privType": "{}{}".format(snmp_config['priv_protocol'], snmp_config['priv_bits'])
                    },
                    "children": [{
                        "snmpUserP": {
                            "attributes": {
                                "adminState": "enabled"
                            }
                        }
                    }]
                }
            }            

            # Set the HTTP headers and URL for the API request
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"APIC-cookie {auth_token}"
            }
            url = f"{apic_url}/api/mo/uni/userext/user-{snmp_config['snmpUser']['attributes']['userName']}.json"

            # Send the API request with the JSON payload
            response = requests.post(url, headers=headers, data=json.dumps(snmp_config), verify=False)

            # Check the API response status code and print the response content
            if response.status_code == 200:
                print("SNMPv3 configuration successfully applied.")
            else:
                print("Error applying SNMPv3 configuration.")
                print(response.content)
        else:
            print(f"{device_type} is not a readable type. The script is sensitive to capitalization.")
            print("The possible DEVICE_TYPES are IOS, NXOS, FXOS, ASA, and ACI")
        
