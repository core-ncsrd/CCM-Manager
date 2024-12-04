General information:
--------------------
script get_host_crypto_data.py is not used anymore, instead main.py calls functions from other py scripts that are dedicated to gathering specific information or doing specific jobs.

Right now we gather information from "openssl ciphers -v", "openssl x509 -noout -text -in <certificate.cer>" where certificate.cer is given manually from the user on the host system, and SSH algorithms information from the command "sudo sshd -T | grep algorithms" 
Further additions to be done tomorrow are:

To be done by 4/12:
-------------------
1. validation of algorithms blocks - check that aliases of algorithms are being inserted as values to the key name of the algorithm (append values to the dictionary) 
2. creation of another .py to gather information from the command "nmap -sV --script ssl-enum-ciphers -p- <hostname>" and cross-check with available ciphers on the system
3. automated send to CCM Manager from the main script
4. check and review of service and trigger

For future use:
---------------
1. utilization of python utility keyfinder

More information to be added by 4/12
