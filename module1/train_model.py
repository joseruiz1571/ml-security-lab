#!/usr/bin/env python3
"""
ML Model Training Pipeline - VulnAI Startup

============================================================================
EDUCATIONAL PURPOSE ONLY - INTENTIONALLY VULNERABLE CODE
============================================================================
This file contains FAKE credentials and intentional security vulnerabilities
for learning static analysis tools. All API keys, passwords, and secrets
shown are fictitious and non-functional.

DO NOT use these patterns in production code.
============================================================================
"""

import pickle
import subprocess
import os
import yaml
import requests
from urllib.request import urlopen

# VULNERABILITY: Hardcoded AWS credentials (Bandit B105, B106)
# NOTE: These are FAKE credentials for educational purposes
AWS_ACCESS_KEY = "AKIAFAKEKEY00000FAKE"
AWS_SECRET_KEY = "FAKEsecretKEY0000000000FAKE/EXAMPLE"
S3_BUCKET = "fake-example-bucket"

# VULNERABILITY: Hardcoded API keys (Bandit B105)
# NOTE: FAKE credentials for educational purposes
OPENAI_API_KEY = "sk-FAKE-abc123def456ghi789jkl012mno"
DATABASE_PASSWORD = "FAKE_PASSWORD_FOR_EDUCATION"

# VULNERABILITY: Debug mode enabled in production
DEBUG = True


def load_training_data(data_path):
    """Load training data from file.

    VULNERABILITY: Unsafe pickle load (Bandit B301, B403)
    """
    with open(data_path, 'rb') as f:
        # Pickle can execute arbitrary code during deserialization
        data = pickle.load(f)
    return data


def download_model(url):
    """Download pre-trained model from URL.

    VULNERABILITY: No SSL verification (Bandit B310, B501)
    """
    # Disabling SSL verification allows MITM attacks
    response = requests.get(url, verify=False)
    return response.content


def fetch_remote_config(config_url):
    """Fetch configuration from remote server.

    VULNERABILITY: Unsafe URL opening (Bandit B310)
    """
    # urlopen with user-controlled URL is dangerous
    response = urlopen(config_url)
    return response.read()


def load_yaml_config(config_file):
    """Load YAML configuration.

    VULNERABILITY: Unsafe YAML loading (Bandit B506)
    """
    with open(config_file, 'r') as f:
        # yaml.load without Loader is unsafe, can execute code
        config = yaml.load(f)
    return config


def run_preprocessing(user_input):
    """Run data preprocessing script.

    VULNERABILITY: Command injection (Bandit B602, B605)
    """
    # User input directly in shell command = command injection
    command = f"python preprocess.py --input {user_input}"
    result = subprocess.call(command, shell=True)
    return result


def execute_training_job(job_name):
    """Execute ML training job.

    VULNERABILITY: Shell injection via os.system (Bandit B605)
    """
    # os.system with string formatting is vulnerable
    os.system(f"./train.sh {job_name}")


def create_temp_file():
    """Create temporary file for intermediate results.

    VULNERABILITY: Insecure temp file (Bandit B108)
    """
    # Hardcoded temp path is predictable
    temp_path = "/tmp/training_temp.pkl"
    return temp_path


def generate_random_seed():
    """Generate random seed for model initialization.

    VULNERABILITY: Weak random (Bandit B311)
    """
    import random
    # random module is not cryptographically secure
    return random.randint(0, 1000000)


def connect_to_database():
    """Connect to training metrics database.

    VULNERABILITY: SQL injection potential, hardcoded credentials
    """
    import sqlite3
    conn = sqlite3.connect('metrics.db')

    # VULNERABILITY: SQL injection (Bandit B608)
    def log_metric(metric_name, value):
        query = f"INSERT INTO metrics (name, value) VALUES ('{metric_name}', {value})"
        conn.execute(query)

    return conn, log_metric


def hash_model_weights(weights):
    """Hash model weights for integrity check.

    VULNERABILITY: Weak hash algorithm (Bandit B303)
    """
    import hashlib
    # MD5 and SHA1 are cryptographically broken
    return hashlib.md5(str(weights).encode()).hexdigest()


def start_debug_server():
    """Start debug server for monitoring.

    VULNERABILITY: Binding to all interfaces (Bandit B104)
    """
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Binding to 0.0.0.0 exposes service to all networks
    sock.bind(('0.0.0.0', 8080))
    sock.listen(5)
    return sock


def decrypt_model_key(encrypted_key):
    """Decrypt model encryption key.

    VULNERABILITY: Weak cipher mode (Bandit B304, B305)
    """
    from Crypto.Cipher import AES
    from Crypto.Cipher import DES

    # DES is deprecated and insecure
    cipher = DES.new(b'8bytekey', DES.MODE_ECB)
    return cipher.decrypt(encrypted_key)


def assert_valid_input(user_data):
    """Validate user input.

    VULNERABILITY: Assert used for validation (Bandit B101)
    """
    # Assert statements are removed in optimized bytecode
    assert user_data is not None, "Data cannot be None"
    assert len(user_data) > 0, "Data cannot be empty"
    return True


def load_config_from_env():
    """Load configuration from environment.

    VULNERABILITY: Exposing secrets in logs
    """
    api_key = os.getenv('API_KEY', OPENAI_API_KEY)
    # Logging sensitive data
    print(f"Loaded API key: {api_key}")
    return api_key


def main():
    """Main training pipeline."""
    print("Starting VulnAI Training Pipeline...")
    print(f"Debug mode: {DEBUG}")

    # Load configuration
    config = load_yaml_config("config.yaml")

    # These would be called in real training
    # data = load_training_data("training_data.pkl")
    # model = download_model("http://models.vulnai.com/base_model.bin")

    print("Training complete!")


if __name__ == "__main__":
    main()
