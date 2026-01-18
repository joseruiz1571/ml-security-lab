#!/usr/bin/env python3
"""
Model Serving API for VulnAI

============================================================================
EDUCATIONAL PURPOSE ONLY - INTENTIONALLY VULNERABLE CODE
============================================================================
This file contains FAKE credentials and intentional security vulnerabilities
for learning static analysis tools. All API keys, passwords, and secrets
shown are fictitious and non-functional.

DO NOT use these patterns in production code.
============================================================================
"""

from flask import Flask, request, jsonify
import pickle
import subprocess
import os
import hashlib
import hmac
import logging

# VULNERABILITY: Hardcoded secrets (Bandit B105)
# NOTE: These are FAKE credentials for educational purposes
API_SECRET_KEY = "FAKE_secret_api_key_for_education"
JWT_SECRET = "FAKE_jwt_signing_secret"
ADMIN_PASSWORD = "FAKE_admin_password"

app = Flask(__name__)

# VULNERABILITY: Debug mode in production (security issue)
app.debug = True


# VULNERABILITY: Logging sensitive data
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class ModelManager:
    """Manage ML model lifecycle."""

    def __init__(self):
        self.models = {}
        # VULNERABILITY: Hardcoded database credentials
        self.db_connection_string = "postgresql://admin:dbpass123@prod-db.vulnai.com:5432/models"

    def load_model(self, model_path):
        """Load model from disk.

        VULNERABILITY: Unsafe pickle (Bandit B301)
        """
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model

    def save_model(self, model, path):
        """Save model to disk."""
        with open(path, 'wb') as f:
            pickle.dump(model, f)

    def download_model_weights(self, url):
        """Download model weights from URL.

        VULNERABILITY: No SSL verification (Bandit B501)
        """
        import requests
        response = requests.get(url, verify=False)
        return response.content

    def verify_model_signature(self, model_data, signature):
        """Verify model signature.

        VULNERABILITY: Weak hash for signature (Bandit B303, B324)
        """
        # SHA1 is deprecated for security purposes
        computed_hash = hashlib.sha1(model_data).hexdigest()
        return computed_hash == signature

    def backup_model(self, model_name, backup_location):
        """Backup model to location.

        VULNERABILITY: Command injection (Bandit B602)
        """
        # User-controlled input in shell command
        cmd = f"cp models/{model_name}.pkl {backup_location}"
        subprocess.call(cmd, shell=True)


manager = ModelManager()


@app.route('/predict', methods=['POST'])
def predict():
    """Run model prediction.

    VULNERABILITY: No input validation, potential for injection
    """
    data = request.get_json()

    # VULNERABILITY: Logging user input (potential sensitive data)
    logger.debug(f"Received prediction request: {data}")

    # No validation of input data
    model_name = data.get('model')
    input_data = data.get('input')

    if model_name not in manager.models:
        return jsonify({'error': 'Model not found'}), 404

    result = manager.models[model_name].predict(input_data)
    return jsonify({'prediction': result})


@app.route('/load_model', methods=['POST'])
def load_model():
    """Load model by path.

    VULNERABILITY: Path traversal, unsafe pickle load
    """
    data = request.get_json()
    # No path validation - allows path traversal
    model_path = data.get('path')

    # VULNERABILITY: Unsafe pickle load with user-controlled path
    model = manager.load_model(model_path)
    manager.models[data.get('name')] = model

    return jsonify({'status': 'loaded'})


@app.route('/execute', methods=['POST'])
def execute_command():
    """Execute system command.

    VULNERABILITY: Remote code execution (Bandit B602, B605)
    """
    data = request.get_json()
    command = data.get('command')

    # VULNERABILITY: Direct command execution from user input
    result = subprocess.check_output(command, shell=True)

    return jsonify({'output': result.decode()})


@app.route('/eval', methods=['POST'])
def evaluate_expression():
    """Evaluate Python expression.

    VULNERABILITY: Code injection via eval (Bandit B307)
    """
    data = request.get_json()
    expression = data.get('expr')

    # VULNERABILITY: eval with user input
    result = eval(expression)

    return jsonify({'result': str(result)})


@app.route('/config', methods=['GET'])
def get_config():
    """Get server configuration.

    VULNERABILITY: Exposing sensitive configuration
    """
    # Exposing secrets in API response
    return jsonify({
        'debug': app.debug,
        'api_key': API_SECRET_KEY,
        'db_connection': manager.db_connection_string
    })


@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload file to server.

    VULNERABILITY: No file validation, path traversal
    """
    file = request.files.get('file')
    filename = file.filename  # User-controlled filename

    # VULNERABILITY: Path traversal - filename not sanitized
    file.save(f"/uploads/{filename}")

    return jsonify({'status': 'uploaded', 'path': filename})


@app.route('/admin/reset', methods=['POST'])
def admin_reset():
    """Reset admin password.

    VULNERABILITY: Hardcoded comparison, timing attack
    """
    data = request.get_json()
    password = data.get('password')

    # VULNERABILITY: Timing attack - string comparison is not constant time
    if password == ADMIN_PASSWORD:
        return jsonify({'status': 'authorized'})
    return jsonify({'status': 'unauthorized'}), 401


def generate_token(user_id):
    """Generate authentication token.

    VULNERABILITY: Weak random for token generation (Bandit B311)
    """
    import random
    import string
    # Not cryptographically secure
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
    return token


def hash_password(password):
    """Hash user password.

    VULNERABILITY: Weak hashing (Bandit B303)
    """
    # MD5 is not suitable for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def verify_webhook(payload, signature):
    """Verify webhook signature.

    VULNERABILITY: Insecure comparison (Bandit B324)
    """
    expected = hmac.new(
        API_SECRET_KEY.encode(),
        payload.encode(),
        hashlib.md5  # MD5 is weak
    ).hexdigest()

    # VULNERABILITY: Not using hmac.compare_digest (timing attack)
    return signature == expected


if __name__ == '__main__':
    # VULNERABILITY: Binding to all interfaces (Bandit B104)
    app.run(host='0.0.0.0', port=5000, debug=True)
