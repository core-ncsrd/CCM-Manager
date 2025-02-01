import os
import logging
import requests
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def search_and_send_dependencies(destination_url):
    try:
        logging.debug("Starting system-wide dependency search...")

        found_dependencies = []

        common_paths = [
            '/',
            '/usr/local/lib',
            '/var/www/html'
        ]

        for search_path in common_paths:
            for root, dirs, files in os.walk(search_path):
                logging.debug(f"Checking directory: {root}")
                if 'pom.xml' in files:
                    found_dependencies.append({"file": os.path.join(root, 'pom.xml'), "language": "java"})
                elif 'requirements.txt' in files:
                    found_dependencies.append({"file": os.path.join(root, 'requirements.txt'), "language": "python"})
                elif 'package.json' in files:
                    found_dependencies.append({"file": os.path.join(root, 'package.json'), "language": "nodejs"})
                elif 'composer.json' in files:
                    found_dependencies.append({"file": os.path.join(root, 'composer.json'), "language": "php"})

        # Check if no dependencies were found
        if not found_dependencies:
            return {"message": "No recognized dependency files found in the system."}

        logging.debug(f"Dependencies found: {found_dependencies}")

        # Prepare the files to send as part of the request
        files_to_send = []
        for dep in found_dependencies:
            file_path = dep["file"]
            with open(file_path, 'rb') as file:
                file_data = file.read()
                files_to_send.append(('file', (os.path.basename(file_path), file_data)))

        data_to_send = {
            "timestamp": datetime.now().isoformat(),
            "dependencies": found_dependencies
        }

        logging.debug(f"Sending data to {destination_url}...")
        response = requests.post(destination_url, files=files_to_send, data=data_to_send)

        if response.status_code == 200:
            logging.debug("Dependencies sent successfully")
            return {"message": "Dependencies sent successfully", "response": response.json()}
        else:
            logging.error(f"Failed to send dependencies. Status Code: {response.status_code}. Response: {response.text}")
            return {
                "error": "Failed to send dependencies",
                "status_code": response.status_code,
                "response_text": response.text
            }

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return {"error": "Internal server error", "details": str(e)}

if __name__ == "__main__":
    destination_url = "http://10.160.101.202:5001/generate_sbom"
    result = search_and_send_dependencies(destination_url)
    if 'error' in result:
        print(f"Error: {result['error']}")
        if 'details' in result:
            print(f"Details: {result['details']}")
    else:
        print("Operation successful:")
        print(result)
