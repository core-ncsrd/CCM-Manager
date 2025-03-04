import json
import os
import time
# import subprocess
import uuid
import logging
from logging.handlers import RotatingFileHandler
# import re
from datetime import datetime
from parsers import parse_security_levels, parse_ciphers_file
from enabled_algorithms import get_disabled_algorithms, get_enabled_algorithms
from ssh_info import get_ssh_crypto_info
from certificates import get_certificate_info
from oids import get_system_oids
from ssl_tls_cipher_info import get_tls_cipher_info, get_nmap_tls_info
from set_ccma_conf_file import log_ccm_data
#from kernels import get_kernel_info ## NOT YET
import requests
# from configure_logger import configure_logger, close_logger
from logger_module import get_logger
import socket


# global custom_id
# custom_id = 22524368

# Starting logger
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)

# # Create rotating file handler for the logger
# max_bytes = 50 * 1024 # 50KB to test the rotation
# backup_count = 30 # up to 30 old log files
# file_handler = RotatingFileHandler('ccm-agent.log', max_bytes, backup_count)
# file_handler.setLevel(logging.INFO)

# # Create formatter of the log file
# script_name = os.path.basename(__name__)
# main_process_id = 22524368

# custom_id = main_process_id

# # logger = configure_logger(script_name, main_process_id)

# # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(custom_id)s: %(message)s')
# #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s')
# file_handler.setFormatter(formatter)

# # Add the handler to the logger
# logger.addHandler(file_handler)

logger = get_logger("MAIN", custom_id=22524368)

logger.info("#--------------------------------------------------#")
logger.info("#----------- INITIATING LOCAL CCM AGENT -----------#")
logger.info("#--------------------------------------------------#")

# Path to the JSON file where we will append data
timestamp = datetime.now().strftime("%y%m%d%H%M%S")
output_file = f"output-{timestamp}.json"
oid_mappings_file = "oid_mappings.json"
algorithms_file = "algorithms-security-levels.txt"

# Function to populate JSON data
def populate_json():
    # Log our entry in the function
    logger.info("Populate oid_mappings.json file with system's hardwired OID information.")

    # First, get the system OIDs and save them in oid_mappings.json
    custom_id = 6750
    get_system_oids()
    custom_id = 22524368

    # Parse the security levels
    logger.info("Parse security levels.")
    custom_id = 4180
    security_levels = parse_security_levels('algorithms-security-levels.txt')
    custom_id = 22524368

    # Load the OID mappings to populate the algorithms-oid block
    logger.info("Load OID mappings JSON file and populate algorithms-oid block.")
    with open(oid_mappings_file, "r") as json_file:
        oids = json.load(json_file)

    # Parse the algorithms file for security levels
    logger.info("Parse the algorithms file to get the security levels.")
    custom_id = 4180
    algorithm_security_levels = parse_security_levels(algorithms_file)
    # Debugging if needed
#    print("Algorithms security levels", algorithm_security_levels)
    custom_id = 22524368

    # Get the list of disabled algorithms
    logger.info("Call upon a function to get the list of the system's disabled algorithms.")
    custom_id = 8446
    disabled_algorithms = get_disabled_algorithms()
    custom_id = 22524368

    # Debugging if needed
#    print("Disabled Algos: ", disabled_algorithms)

    # Filter out the disabled algorithms
    logger.info("Filter out disabled algorithms from the list the CCM Agent sends to the CCM Manager.")
    custom_id = 8446
    algos = get_enabled_algorithms()
    # Debugging if needed
    #print("enabled Algos: ", algos)
    custom_id = 22524368

    # Load the OID mappings
    logger.info("Load the OID mappings JSON file for update.")
    with open("oid_mappings.json", "r") as json_file:
        algorithms = json.load(json_file)

    # Update algorithms with security levels
    logger.info("update the algorithms with their respective security level.")
    for algo in algorithms:
        name = algo.get("name", "").strip()
        if name in security_levels:
            algo.update(security_levels[name])

    # Gather SSH crypto info (ciphers, MACs, KEX, etc.)
    logger.info("Call upon function to gather SSH crypto information (ciphers, MACs, KEX, etc).")
    custom_id = 4253
    ssh_crypto_info = get_ssh_crypto_info()
    custom_id = 22524368

    # Filter algorithms to ensure only matching ones stay
#    ssh_crypto_info, algorithms = filter_matching_algorithms(ssh_crypto_info, algorithms)

    # Get cipher details from calling on the function get_tls_cipher_info() which executes the command "openssl ciphers -v"
    logger.info("Call upon function to gather TLS cipher details by executing the command \"openssl ciphers -v\".")
    custom_id = 6101
    ciphers = get_tls_cipher_info()
    custom_id = 22524368

    # Append security levels to the algorithms
    # algorithms = append_security_levels_to_algorithms(algorithms, security_levels)
    # Update cipher data with security levels
    logger.info("Upate cipher data gathered with their respective security levels.")
    for cipher_name, cipher in ciphers.items():
        if cipher_name in security_levels:
            cipher["classicSecurityLevel"] = security_levels[cipher_name]["classicSecurityLevel"]

    # # Get nmap TLS information of the host
    logger.info("Call upon function to gather nmap TLS information from the host.")
    custom_id = 6101
    nmap_tls_dets = get_nmap_tls_info()
    custom_id = 22524368

    # Get certificate information by calling on the function get_certificate_info()
    logger.info("Call upon function to gather certificate centric information of the host.")
    custom_id = 5280
    certificate_info = get_certificate_info()
    custom_id = 22524368

    # Get kernel info from executing cat /proc/crypto to be used in the creation of the CBOM file in the API
    # custom_id = 1337
    #kernels = get_kernel_info() ## TO BE IMPLEMENTED LATER
    # custom_id = 22524368

    logger.info("Construct data structure to collect cryptographic related information to send to the CCM Manager API.")
    data = {
        "oid_refs": algos,
        "ciphers": {"tls" : ciphers},
        "nmap_tls_info": nmap_tls_dets,
        "certificate": certificate_info,
        "ssh_crypto_info": ssh_crypto_info,
#        "kernel_crypto_info": kernels ## LATER
    }

    # Append to the JSON file
    logger.info("Append data structure to the final file.")
    with open(output_file, "w") as json_file:
        json.dump(data, json_file, indent=2)

# def send_json_to_api(file_path, api_url):
#     logger.info("Trying to send file %s to the CCM Manager..........", file_path)
#     if not os.path.exists(file_path):
#         logger.error("[%s]: Error: file %s does not exist.", file_path)
#         return None

#     try:
#         with open(file_path, 'rb') as json_file:
#             files = {
#                 'file': (os.path.basename(file_path), json_file, 'application/json'),
#             }
#             response = requests.post(api_url, files=files)
#             response.raise_for_status()  # Raise an HTTPError for bad responses (4xx, 5xx)
#             logger.info("File %s successfully sent to %s. Response: %s", file_path, api_url, response.text)
#             return response.json()
#     except requests.exceptions.RequestException as e:
#         logger.error("[%s]: Error sending file %s to CCM Manager API %s: %s", file_path, api_url, e)
#         return None

def send_files_to_api(main_file_path, api_url):
    hostname = socket.gethostname()
    local_conf_file = f"ccm-a-{hostname}-local.conf"
    local_log_file = f"ccm-a-{hostname}-local-conf.log"

    # Check if all files exist
    files_to_send = {
        "main_file": (main_file_path, "application/json"),
        "local_conf_file": (local_conf_file, "application/json")
        #"local_log_file": (local_log_file, "text/plain"),
    }

    for key, (file_path, mime_type) in files_to_send.items():
        if not os.path.exists(file_path):
            logger.error("Error: %s (%s) does not exist.", key, file_path)
            return None

        try:
            with open(file_path, 'rb') as file:
                files = {key: (os.path.basename(file_path), file, mime_type)}

                logger.info("Sending %s to API...", file_path)
                response = requests.post(api_url, files=files)
                response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)

                logger.info("File %s successfully sent to %s. Response: %s", file_path, api_url, response.text)

        except requests.exceptions.RequestException as e:
            logger.error("Error sending files to CCM Manager API %s: %s", api_url, e)
            return None
        except Exception as e:
            logger.error("An unexpected error occurred while preparing files: %s", e)
            return None
    return True

# Execute script
if __name__ == "__main__":
    start_time = time.time()
    
    log_ccm_data()
    populate_json()
    
    logger.info("Data appended to %s.", output_file)

    logger.info("Sending %s to CCM Manager for further proscessing...", output_file)
    logger.info("Trying to connect with CCM Manager...")

    # file_path = output_file  # Ensure the variable is used correctly
    # api_url = "http://10.160.101.202:5001/receive_output"
    # response = send_json_to_api(file_path, api_url)  # Capture the response here
    # if isinstance(response, dict) and "error" in response:
    #     logger.error("[%s]: Error sending {output_file} to API:", response)
    # else:
    #     logger.info(f"{output_file} sent to CCM Manager. API response:", response)

    main_file_path = output_file
    
    print(main_file_path, "_________________________________")  # Ensure the variable is used correctly
    api_url = "http://10.160.101.202:5001/receive_output"
    response = send_files_to_api(main_file_path, api_url)  # Capture the response here

    if response is None:
        logger.error("Error sending %s to API.", output_file)
    elif isinstance(response, dict) and "error" in response:
        logger.error("Error sending %s to API: %s", output_file, response)
    else:
        logger.info("%s successfully sent to CCM Manager. API response: %s", output_file, response)

    end_time = time.time()
    # Calculate elapsed time in seconds
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(int(elapsed_time), 60)
    logger.info("*** Total time elapsed: %s minutes %s seconds ***", minutes, seconds)
    print(f"*** Total time elapsed: {minutes} minutes {seconds} seconds ***")
    logger.info("#--------------------------------------------------#")
    logger.info("#----------- TERMINATING LOCAL CCM AGENT ----------#")
    logger.info("#--------------------------------------------------#")
    # if not logger.handlers:
    #     handler = logging.StreamHandler()
    #     logger.addHandler(handler)
    #     logger.handlers[0].flush()
    #     logger.handlers[0].close()