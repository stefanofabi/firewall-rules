import mysql.connector
import subprocess
import netifaces as ni
import json
import re

# Read the configuration from the config.json file
with open('config.json') as config_file:
    config = json.load(config_file)

# Define the local IP patterns
local_ip_patterns = [
    re.compile(r'^127\.'),            # IP local de loopback
    re.compile(r'^0\.'),              # IP reservada 0.0.0.0
    re.compile(r'^169\.254\.'),       # IP de autoconfiguración
    re.compile(r'^10\.'),             # Rango privado 10.0.0.0 - 10.255.255.255
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'), # Rango privado 172.16.0.0 - 172.31.255.255
    re.compile(r'^192\.168\.'),        # Rango privado 192.168.0.0 - 192.168.255.255
]

def is_local_ip(ip):
    return any(pattern.match(ip) for pattern in local_ip_patterns)

# Get all IP addresses of the host machine
host_ips = []
for interface in ni.interfaces():
    addresses = ni.ifaddresses(interface)
    if ni.AF_INET in addresses:
        for addr_info in addresses[ni.AF_INET]:
            ip = addr_info['addr']
            if not is_local_ip(ip):
                host_ips.append(ip)

# Convert the IP addresses to SQL list format
ip_list = "', '".join(host_ips)
if ip_list:
    ip_list = f"'{ip_list}'"
else:
    ip_list = 'NULL'

# Establish the connection to the database using the configuration from the JSON file
connection = mysql.connector.connect(
    host=config["host"],
    user=config["user"],
    password=config["password"],
    database=config["database"],
    charset=config["charset"]
)

# Create a cursor to execute queries
cursor = connection.cursor()

# SQL query to get firewall rules
query = f"""
SELECT 
    source_ip, 
    flow, 
    protocol, 
    COALESCE(NULLIF(TRIM(network_addresses.ip_address), ''), 'ANY') AS network_address, 
    COALESCE(NULLIF(TRIM(destination_port), ''), 'ANY') AS destination_port, 
    action 
FROM 
    firewall_rules
LEFT JOIN 
    network_addresses 
ON 
    firewall_rules.network_address_id = network_addresses.id
WHERE 
    (network_addresses.ip_address IN ({ip_list}) OR network_addresses.ip_address IS NULL)
"""

cursor.execute(query)

# Fetch the results
results = cursor.fetchall()

print("Number of firewall rules:", cursor.rowcount)

# Flush iptables rules
subprocess.run("iptables -F", shell=True)

# Print results and apply iptables rules
for row in results:
    source_ip = row[0]
    flow = row[1]
    protocol = row[2]
    network_address = row[3]
    destination_port = row[4]
    action = row[5]

    # Skip if source_ip is a local IP address
    if is_local_ip(source_ip):
        continue

    print("Source IP:", source_ip)
    print("Flow:", flow)
    print("Protocol:", protocol)
    print("Network Address:", network_address)
    print("Destination Port:", destination_port)
    print("Action:", action)
    print()

    # Construct iptables commands
    if flow == 'INPUT':
        flow_flag = '-A INPUT'
    elif flow == 'OUTPUT':
        flow_flag = '-A OUTPUT'
    else:
        continue  # Skip if flow is not recognized

    if protocol == 'ANY':
        protocol_flag = ''
    elif protocol in ['TCP', 'UDP']:
        protocol_flag = f'-p {protocol.lower()}'
    else:
        continue  # Skip if protocol is not recognized

    source_ip_flag = f'-s {source_ip}'

    if network_address == 'ANY' or network_address is None:
        network_address_flag = ''
    else:
        network_address_flag = f'-d {network_address}'

    if destination_port == 'ANY' or destination_port is None:
        port_flag = ''
    else:
        port_flag = f'--dport {destination_port}'

    # Construct the iptables command
    if action == 'ACCEPT':
        action_flag = '-j ACCEPT'
    elif action == 'DROP':
        action_flag = '-j DROP'
    else:
        continue  # Skip if action is not recognized

    command = f"iptables {flow_flag} {protocol_flag} {source_ip_flag} {network_address_flag} {port_flag} {action_flag}"
    
    # Print the command that will be executed
    print(f"Executing command: {command}")
    
    # Execute the iptables command
    subprocess.run(command, shell=True)

# Close cursor and connection
cursor.close()
connection.close()
