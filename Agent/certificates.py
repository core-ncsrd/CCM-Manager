import subprocess
import re
import os

# Helper function to get the certificate of the host being validated
def find_certificate():
# List of common directories to search for certificates
    cert_directories = [
        "/etc/ssl/certs",
        "/usr/share/ca-certificates",
        "/var/lib/ca-certificates",
        "/etc/pki/tls/certs",
        "/etc/ssl",
        "/etc/pki/ca-trust/extracted",
#        os.path.expanduser("~")  # User's home directory
    ]

    # Extensions of certificate files to search for
    cert_extensions = ["*.crt", "*.pem", "*.cer"]

    user_home = os.path.expanduser("~")

    for cert_dir in cert_directories:
        if os.path.exists(cert_dir) and os.path.isdir(cert_dir):
            for root, dirs, files in os.walk(cert_dir):
                # Skip the user's home directory
                if root.startswith(user_home):
                    continue

                for file in files:
                    if file.endswith((".crt", ".cer", ".pem")):  # Check for common certificate file extensions
                        cert_path = os.path.join(root, file)
                        print(f"Found certificate: {cert_path}")
                        return cert_path

    print("No certificate found in common directories.")
    return None


# Helper function to get certificate information from openssl x509 command
def get_certificate_info():
    # Ask the user for the path to the certificate file
    cert_path = input("Please enter the path to the certificate file: ")

    # Dynamic search of usual certificate locations in the host system
#    cert_path = find_certificate()

    if not cert_path:
        print("Certificate not found. Exiting.")
        return {}

    print(f"Using certificate at: {cert_path}")

    command = ["openssl", "x509", "-noout", "-text", "-in", cert_path]
    try:
       output = subprocess.check_output( command, text=True)
    except subprocess.CallProcessError as e:
       print(f"Error executing command: {e}")
       return {}

    certificate_data = {}
    # Define regex for each piece of data to extract
    issuer_regex = r"Issuer: (.*)"
    subject_regex = r"Subject: (.*)"
    validity_not_before_regex = r"Not Before: (.*)"
    validity_not_after_regex = r"Not After : (.*)"
    signature_algorithm_regex = r"Signature Algorithm: (.*)"
    public_key_algorithm_regex = r"Public Key Algorithm: (.*)"
    public_key_regex = r"Public-Key: (.*)"

    certificate_data['issuerName'] = re.search(issuer_regex, output).group(1)
    certificate_data['subjectName'] = re.search(subject_regex, output).group(1)
    certificate_data['notValidBefore'] = re.search(validity_not_before_regex, output).group(1)
    certificate_data['notValidAfter'] = re.search(validity_not_after_regex, output).group(1)
    certificate_data['signatureAlgorithm'] = re.search(signature_algorithm_regex, output).group(1)
    certificate_data['publicKeyAlgorithm'] = re.search(public_key_algorithm_regex, output).group(1)

    # Check if RSA public key exists in the certificate
    rsa_match = re.search(public_key_regex, output)
    certificate_data['rsaPublicKey'] = rsa_match.group(1) if rsa_match else "Not Available"

    certificate_data['rsaPublicKey'] = re.search(public_key_regex, output).group(1)
    if rsa_match:
        rsa_public_key = rsa_match.group(1)
        # Remove parentheses and spaces
        rsa_public_key_clean = rsa_public_key.replace('(', '').replace(')', '').strip()
        certificate_data['rsaPublicKey'] = rsa_public_key_clean

    return certificate_data
