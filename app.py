from flask import Flask, request, jsonify
import subprocess
import tempfile
import json

app = Flask(__name__)

def generate_sbom(image_name):
    with tempfile.NamedTemporaryFile(delete=False) as sbom_file:
        sbom_file_name = sbom_file.name

    # Run Syft to generate SBOM
    subprocess.run(["syft", image_name, "-o", "json", "--file", sbom_file_name])

    # Load SBOM data
    with open(sbom_file_name, "r") as file:
        sbom_data = json.load(file)

    return sbom_data

@app.route("/validate", methods=["POST"])
def validate_pod():
    request_data = request.get_json()

    # Capture the UID from the admission request
    uid = request_data["request"]["uid"]

    # Extract image details from the Pod spec
    image = request_data["request"]["object"]["spec"]["containers"][0]["image"]

    # Prepare the AdmissionReview response
    try:
        sbom = generate_sbom(image)
        # Create an allowed AdmissionReview response with SBOM data
        response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": True,
                "status": {
                    "message": "SBOM generated successfully."
                }
            }
        }
    except Exception as e:
        # Handle errors by denying the request
        response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": False,
                "status": {
                    "message": f"Error generating SBOM: {e}"
                }
            }
        }

    return jsonify(response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context=("/certs/tls.crt", "/certs/tls.key"))
