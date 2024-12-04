import subprocess
import json
import re

def get_tls_cipher_info():
    # Use openssl ciphers -v to gather information about the ciphers
    command = ["openssl", "ciphers", "-v"]
    try:
        output = subprocess.check_output(command, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return {}

    tls_info = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Each line consists of several pieces of information, so we split by spaces
        parts = line.split()

        # Extract cipher name (the first part of the line)
        cipher_name = parts[0]

        # Extract TLS version (second part of the line)
        tls_version = parts[1]

        # Extract key exchange algorithm (third part of the line)
        key_exchange_algorithm = parts[2].split("=")[1] if "Kx=" in parts[2] else "N/A"

        # Extract authentication (fourth part of the line)
        authentication = parts[3].split("=")[1] if "Au=" in parts[3] else "N/A"

        # Extract encryption algorithm (fifth part of the line)
        encryption_algorithm = parts[4].split("=")[1] if "Enc=" in parts[4] else "N/A"

        # Extract MAC algorithm (sixth part of the line)
        mac = parts[5].split("=")[1] if "Mac=" in parts[5] else "N/A"

        # Create a dictionary for the cipher
        tls_info[cipher_name] = {
            "TLS_version": tls_version,
            "key_exchange_algorithm": key_exchange_algorithm,
            "authentication": authentication,
            "encryption_algorithm": encryption_algorithm,
            "mac": mac
        }
    return tls_info


#if __name__ == "__main__":
#    # Get TLS cipher information
#    tls_cipher_info = get_tls_cipher_info()
#    print("TLS Cipher Info:")
#    print(json.dumps(tls_cipher_info, indent=2))
