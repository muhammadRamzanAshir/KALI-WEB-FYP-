import subprocess
import re

def get_network_info():
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        output = result.stdout
        networks = parse_iwconfig_output(output)
        return networks
    except Exception as e:
        return str(e)

def parse_iwconfig_output(output):
    networks = []
    lines = output.split("\n")
    for line in lines:
        if "ESSID" in line:
            essid = re.search(r'ESSID:"(.*?)"', line).group(1)
            networks.append(essid)
    return networks
