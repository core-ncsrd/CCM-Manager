from flask import Flask, jsonify, request
from pymongo import MongoClient
from werkzeug.utils import secure_filename
import os
import logging
import subprocess
from datetime import datetime
import requests
import stat
import glob
from dotenv import load_dotenv 

app = Flask(__name__)

# Configuration settings
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit to 16 MB
client: MongoClient = MongoClient('mongodb://localhost:27017/')  # MongoDB connection
db = client.mydatabase
collection = db.mycollection
load_dotenv()

UPLOAD_FOLDER = './sboms'  # Directory to save SBOMs
TMP_FOLDER = './tmp'  # Directory to save temporary files
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(TMP_FOLDER, exist_ok=True)  # Create tmp directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # Use the defined upload folder
ALLOWED_EXTENSIONS = {'txt'}
DEPENDENCY_TRACK_URL = os.getenv("DEPENDENCY_TRACK_URL")
API_KEY = os.getenv("API_KEY")

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return jsonify({"message": "Flask API with MongoDB is running"})

@app.route('/generate_sbom', methods=['POST'])
def generate_sbom():
    try:
        # Log what Flask receives in the request for debugging
        logging.debug(f"Request files: {request.files}")
        logging.debug(f"Request form: {request.form}")

        if 'file' not in request.files:
            return jsonify({"error": "No file part in request"}), 400
        
        requirements_file = request.files['file']
        
        if requirements_file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        if not allowed_file(requirements_file.filename):
            return jsonify({"error": "Only .txt files are allowed"}), 400

        requirements_filename = secure_filename(requirements_file.filename)

        # Save the requirements file to the tmp directory
        tmp_filepath = os.path.join(TMP_FOLDER, f'{datetime.now().strftime("%Y%m%d%H%M%S")}_{requirements_filename}')
        requirements_file.save(tmp_filepath)
        logging.info(f"Requirements file saved at: {tmp_filepath}")

        # Generate SBOM with the saved requirements file
        sbom_filepath, timestamp = generate_sbom_with_script(tmp_filepath)

        if sbom_filepath:
            logging.info(f"SBOM successfully generated at {sbom_filepath}")
            return jsonify({"message": "SBOM generated successfully", "sbom_file": sbom_filepath}), 200
        else:
            logging.error("Failed to generate SBOM.")
            return jsonify({"error": "Failed to generate SBOM"}), 500

    except Exception as e:
        logging.error(f"An error occurred while uploading requirements.txt: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/upload_sbom', methods=['POST'])
def upload_sbom():
    try:
        # Find the latest SBOM file in the upload folder
        sbom_files = glob.glob(os.path.join(UPLOAD_FOLDER, 'sbom_*.json'))
        if not sbom_files:
            return jsonify({"error": "No SBOM file found"}), 404
        
        # Sort the files by modification time and get the latest one
        sbom_filepath = max(sbom_files, key=os.path.getmtime)

        if not os.path.exists(sbom_filepath):
            return jsonify({"error": "SBOM file not found"}), 404

        logging.info(f"Latest SBOM file found: {sbom_filepath}")
        
        # Extract the project name from the SBOM filename
        project_name = os.path.splitext(os.path.basename(sbom_filepath))[0]
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

        # Create project and upload SBOM to Dependency-Track
        project_uuid = create_project_in_dependency_track(project_name, timestamp)
        if not project_uuid:
            return jsonify({"error": "Failed to create project in Dependency-Track"}), 500
        
        # Upload SBOM to Dependency-Track and retrieve vulnerabilities
        vulnerabilities = upload_sbom_to_dependency_track(sbom_filepath, project_uuid)

        if vulnerabilities:
            # Save to MongoDB
            collection.insert_one({
                'project_name': project_name,
                'project_version': timestamp,
                'vulnerabilities': vulnerabilities
            })
            logging.info("Vulnerabilities data saved to MongoDB")
            return jsonify({"message": "SBOM uploaded and vulnerabilities saved successfully"}), 200
        else:
            logging.error("Failed to get vulnerabilities from Dependency-Track.")
            return jsonify({"error": "Failed to get vulnerabilities from Dependency-Track"}), 500

    except Exception as e:
        logging.error(f"An error occurred while uploading SBOM: {e}")
        return jsonify({"error": "Internal server error"}), 500

def generate_sbom_with_script(filepath: str):
    try:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        output_sbom_file = os.path.join(app.config['UPLOAD_FOLDER'], f'sbom_{timestamp}.json')

        # Run the shell script for SBOM generation
        result = subprocess.run(
            ['./generate_sbom.sh', filepath, timestamp],
            check=True,
            capture_output=True,
            text=True
        )

        logging.info(f"SBOM generation output: {result.stdout}")
        logging.error(f"SBOM generation error: {result.stderr}")

        # Check if the SBOM file was created
        if not os.path.exists(output_sbom_file):
            logging.error(f"SBOM file was not created: {output_sbom_file}")
            return None, None

        # Change the file permissions to make it readable for everyone
        os.chmod(output_sbom_file, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # r--r--r--

        return output_sbom_file, timestamp

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running SBOM generation script: {e}")
        return None, None

    except Exception as e:
        logging.error(f"Error in SBOM generation function: {e}")
        return None, None

def create_project_in_dependency_track(project_name: str, project_version: str):
    try:
        payload = {
            'name': project_name,
            'version': project_version,
            'active': True  # Set the project to active
        }

        headers = {
            "X-Api-Key": API_KEY,
            "Content-Type": "application/json"
        }

        # Send a PUT request to create/update the project
        response = requests.put(
            DEPENDENCY_TRACK_URL,
            headers=headers,
            json=payload,
            verify=False  # Set to True if using HTTPS with valid certificates
        )

        logging.info(f"Response from Dependency-Track (Create/Update Project): {response.status_code} - {response.text}")

        if response.status_code in [200, 201]:
            project_data = response.json()
            project_uuid = project_data.get('uuid')
            logging.info(f"Project created/updated successfully with UUID: {project_uuid}")
            return project_uuid
        else:
            logging.error(f"Failed to create or update project. Status code: {response.status_code}. Message: {response.text}")
            return None
    except Exception as e:
        logging.error(f"Error creating project in Dependency-Track: {e}")
        return None

def upload_sbom_to_dependency_track(sbom_filepath: str, project_uuid: str):
    try:
        upload_url = f"{DEPENDENCY_TRACK_URL}/api/v1/bom"

        logging.info(f"Attempting to upload SBOM to: {upload_url}")
        logging.info(f"SBOM File Path: {sbom_filepath}")
        logging.info(f"Project UUID: {project_uuid}")

        with open(sbom_filepath, 'rb') as sbom_file:
            files = {
                'bom': ('sbom.json', sbom_file, 'application/json'),
                'project': (None, project_uuid)
            }

            # Post the SBOM to Dependency-Track
            response = requests.post(
                upload_url,
                headers={"X-Api-Key": API_KEY},
                files=files,
                verify=False  # Skip SSL verification if necessary
            )

            logging.info(f"Response from Dependency-Track (SBOM Upload): {response.status_code} - {response.text}")

            if response.status_code in [200, 201, 202]:
                logging.info(f"SBOM uploaded successfully for project UUID {project_uuid}")
                return get_project_vulnerabilities(project_uuid, API_KEY, DEPENDENCY_TRACK_URL)
            else:
                logging.error(f"SBOM upload failed. Status code: {response.status_code}. Message: {response.text}")
                return None
    except Exception as e:
        logging.error(f"Error uploading SBOM to Dependency-Track: {e}")
        return None

def get_project_vulnerabilities(project_uuid: str, api_key: str, base_url: str):
    try:
        vuln_api_url = f"{base_url}/api/v1/vulnerability/project/{project_uuid}"

        response = requests.get(
            vuln_api_url,
            headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
            verify=False  # Set to True if using valid SSL certificates
        )

        if response.status_code == 200:
            vulnerabilities = response.json()
            logging.info(f"Found {len(vulnerabilities)} vulnerabilities for project UUID {project_uuid}")
            return vulnerabilities
        else:
            logging.error(f"Failed to fetch vulnerabilities: {response.status_code}. Message: {response.text}")
            return None

    except Exception as e:
        logging.error(f"Error fetching vulnerabilities: {e}")
        return None

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
