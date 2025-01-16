import os
import socket
import uuid
import hashlib
import time
from datetime import datetime
import json
import logging
import subprocess
import re

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('ccm-a-local-conf.log')

#formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s')
script_name = os.path.basename(__file__)  # Get the script name
formatter = logging.Formatter(
    f'%(asctime)s - {script_name} - [%(process)d] - %(levelname)s: %(message)s'
)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

def log_ccm_data():
    logger.info("Gathering host information for the stable file....")
    # Get hostname
    hostname = socket.gethostname()
    logger.info("Running on %s", hostname)

    # Generate UUID and timestamp ID
    # We want UUID to be unique and only set on the first run of the CCM Agent
    # Check if file exists and load data if it does


    ccma_id = str(uuid.uuid4())
    tID = datetime.now().strftime('%Y%m%d-%H%M%S-') + str(uuid.uuid4())
    logger.info("Generated ccma_id = %s", ccma_id)
    logger.info("Generated tID = %s", tID)
    
    # Hash IDs with SHA256
    hashed_ccma_id = hashlib.sha256(ccma_id.encode('utf-8'), usedforsecurity=True).hexdigest()
    hashed_tID = hashlib.sha256(tID.encode('utf-8'), usedforsecurity=True).hexdigest()
    logger.info("Hashing ccma_id and tID....")
    logger.info("Hashed ccma_id = %s", hashed_ccma_id)
    logger.info("Hashed tID = %s", hashed_tID)

    # Create filename based on hostname and hashed IDs
    filename = f"ccm-a-{hostname}-local.conf"
    logger.info("Creating file to save local CCM Agent information named %s.", filename)

    # Get the MAC address of eth0
    def get_mac_address():
        try:
	    # Execute the 'ip a' command and capture its output
            result = subprocess.run(['ip', 'a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
            # Check if the command ran successfully
            if result.returncode != 0:
                logger.error(f"Failed to execute 'ip a': {result.stderr.strip()}")
                raise RuntimeError(f"Failed to execute 'ip a': {result.stderr.strip()}")
        
            # Search for the specified interface's MAC address
            # Use regex to find the second interface's MAC address
            # Match "2: <interface name> ... \n    link/ether <MAC address> brd ..."
            pattern = r"2:\s([\w\d\-]+):.*?\n\s+link/ether\s([0-9a-f:]+)"
            match = re.search(pattern, result.stdout, re.IGNORECASE)
        
            if match:
                interface = match.group(1)  # The interface name
                mac_address = match.group(2)    # The MAC address
                # print(f"Interface: {interface_name}, MAC: {mac_address}")
                return mac_address  # Return the MAC address
            else:
                logger.error(f"MAC address for interface '{interface}' not found.")
                raise ValueError(f"MAC address for interface '{interface}' not found.")

        except Exception as e:
            logger.error("Error getting the system's MAC address.")
            return "00:00:00:00:00:00"  # Default MAC if error occurs
    
    mac_address = get_mac_address()
    
    # Initialize data dictionary
    data = {
        "hashed_ccma_id": None,
        "hashed_tID": hashed_tID,
        "mac_address": mac_address,
        "first_run": None,  # To be set only on first run
        "last_update": datetime.now().isoformat(),
    }
    
    # Check if file exists and load data if it does
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_data = json.load(f)
            data["first_run"] = existing_data.get("first_run", data["last_update"])
    else:
        # Set first_run as the current datetime if this is the first run
        data["first_run"] = data["last_update"]
    
    # Write data back to the file
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    
    logger.info(f"CCM Agent was first run on the system {hostname} with UUID {hashed_ccma_id} on : %s", data["first_run"])
    logger.info("CCM Agent was last run on: %s", data["last_update"])
    logger.info(f"Data logged successfully in {filename}")


# Run the function
# log_ccm_data()
