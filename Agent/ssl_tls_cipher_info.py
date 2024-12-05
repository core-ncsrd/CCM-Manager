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


def get_nmap_tls_info():
    # Run the nmap command to get TLS ciphers
    command_nmap = ["nmap", "-sV", "--script", "ssl-enum-ciphers", "-p-", "localhost"]
    try:
        output_nmap = subprocess.check_output(command_nmap, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e}")
        return {}

    # Run the openssl command to get cipher details
    command_openssl = ["openssl", "ciphers", "-v"]
    try:
        output_openssl = subprocess.check_output(command_openssl, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing openssl command: {e}")
        return {}

    # Parse OpenSSL output into a dictionary for quick lookup
    openssl_ciphers = {}
    for line in output_openssl.splitlines():
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 5:
            cipher_name = parts[0]
            tls_version = parts[1]
            kx = parts[2].split('=')[1]
            au = parts[3].split('=')[1]
            enc_info = parts[4].split('=')[1]
             # Safely extract encryption and bits
            enc_match = re.match(r'(\w+)\((\d+)\)', enc_info)
            if enc_match:
                enc, bits = enc_match.groups()
            else:
                enc, bits = enc_info, "N/A"  # Default values if no match
#            if '(' in enc_info:
#                enc, bits = re.match(r'(\w+)\((\d+)\)', enc_info).groups()
#            else:
#                enc, bits = enc_info, "N/A"
            mac = parts[5].split('=')[1] if len(parts) > 5 else "N/A"

            openssl_ciphers[cipher_name] = {
                "tls_version": tls_version,
                "kexalgo": kx,
                "authentication": au,
                "encryption_algorithm": enc,
                "bits": bits,
                "mac": mac,
            }

    # Parse Nmap output to gather TLS cipher information
    nmap_tls_info = {}
    current_tls_version = None
    for line in output_nmap.splitlines():
        line = line.strip()
        if line.startswith("TLS"):
            current_tls_version = line.split(":")[0].strip()
            nmap_tls_info[current_tls_version] = {}
        elif line.startswith("TLS_") and current_tls_version:
            cipher_name = line.split(" ")[0].strip()
            if cipher_name in openssl_ciphers:
                details = openssl_ciphers[cipher_name]
                nmap_tls_info[current_tls_version][cipher_name] = {
                    "name": cipher_name,
                    "tls_version": details["tls_version"],
                    "kexalgo": details["kexalgo"],
                    "authentication": details["authentication"],
                    "encryption_algorithm": details["encryption_algorithm"],
                    "bits": details["bits"],
                    "mac": details["mac"],
                }
            else:
                # Handle missing ciphers in OpenSSL details
                nmap_tls_info[current_tls_version][cipher_name] = {
                    "name": cipher_name,
                    "tls_version": current_tls_version,
                    "kexalgo": "unknown",
                    "authentication": "unknown",
                    "encryption_algorithm": "unknown",
                    "bits": "unknown",
                    "mac": "unknown",
                }

    return nmap_tls_info


#if __name__ == "__main__":
#    # Get TLS cipher information
#    tls_cipher_info = get_tls_cipher_info()
#    print("TLS Cipher Info:")
#    print(json.dumps(tls_cipher_info, indent=2))
