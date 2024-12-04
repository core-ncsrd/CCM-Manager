import json
# import subprocess
# import uuid
# import re
from datetime import datetime
from parsers import parse_security_levels, parse_ciphers_file
from enabled_algorithms import get_disabled_algorithms, get_enabled_algorithms
from ssh_info import get_ssh_crypto_info
from certificates import get_certificate_info
from oids import get_system_oids
from ssl_tls_cipher_info import get_tls_cipher_info
#from kernels import get_kernel_info ## NOT YET
#import requests

# Path to the JSON file where we will append data
timestamp = datetime.now().strftime("%y%m%d%H%M%S")
output_file = f"output-{timestamp}.json"
oid_mappings_file = "oid_mappings.json"
algorithms_file = "algorithms-security-levels.txt"

# Function to populate JSON data
def populate_json():
    # First, get the system OIDs and save them in oid_mappings.json
    get_system_oids()

    # Parse the security levels
    security_levels = parse_security_levels('algorithms-security-levels.txt')

    # Load the OID mappings to populate the algorithms-oid block
    with open(oid_mappings_file, "r") as json_file:
        oids = json.load(json_file)

    # Parse the algorithms file for security levels
    algorithm_security_levels = parse_security_levels(algorithms_file)
    # Debugging if needed
#    print("Algorithms security levels", algorithm_security_levels)

    # Get the list of disabled algorithms
    disabled_algorithms = get_disabled_algorithms()

    # Debugging if needed
#    print("Disabled Algos: ", disabled_algorithms)

    # Filter out the disabled algorithms
    algos = get_enabled_algorithms()
    # Debugging if needed
#    print("enabled Algos: ", algorithms)

    # Load the OID mappings
    with open("oid_mappings.json", "r") as json_file:
        algorithms = json.load(json_file)

    # Update algorithms with security levels
    for algo in algorithms:
        name = algo.get("name", "").strip()
        if name in security_levels:
            algo.update(security_levels[name])

    # Gather SSH crypto info (ciphers, MACs, KEX, etc.)
    ssh_crypto_info = get_ssh_crypto_info()

    # Filter algorithms to ensure only matching ones stay
#    ssh_crypto_info, algorithms = filter_matching_algorithms(ssh_crypto_info, algorithms)

    # Get cipher details from calling on the function get_tls_cipher_info() which executes the command "openssl ciphers -v"
    ciphers = get_tls_cipher_info()

    # Append security levels to the algorithms
    # algorithms = append_security_levels_to_algorithms(algorithms, security_levels)
    # Update cipher data with security levels
    for cipher_name, cipher in ciphers.items():
        if cipher_name in security_levels:
            cipher["classicSecurityLevel"] = security_levels[cipher_name]["classicSecurityLevel"]



    # Get certificate information by calling on the function get_certificate_info() 
    certificate_info = get_certificate_info()

    # Get kernel info from executing cat /proc/crypto to be used in the creation of the CBOM file in the API
    #kernels = get_kernel_info() ## TO BE IMPLEMENTED LATER

    data = {
        "algorithms": algos,
        "ciphers": ciphers,
        "certificate": certificate_info,
        "ssh_crypto_info": ssh_crypto_info,
#        "kernel_crypto_info": kernels ## LATER
    }

    # Append to the JSON file
    with open(output_file, "w") as json_file:
        json.dump(data, json_file, indent=2)

# Execute script
if __name__ == "__main__":
    populate_json()
    print(f"Data appended to {output_file}")

    print(f"Sending {output_file} to CCM Manager for further processing...")
