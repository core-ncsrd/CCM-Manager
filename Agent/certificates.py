import subprocess
import re

# Helper function to get certificate information from openssl x509 command
def get_certificate_info():
    # Ask the user for the path to the certificate file
    cert_path = input("Please enter the path to the certificate file: ")

    command = ["openssl", "x509", "-noout", "-text", "-in", cert_path]
    output = subprocess.check_output( command, text=True)

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
