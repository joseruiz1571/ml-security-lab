#!/usr/bin/env python3
"""
CryptoTrade Pro - Model Management Module

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
import os
import hashlib
import requests
from pathlib import Path

# VULNERABILITY: Hardcoded API credentials (Bandit B105)
# NOTE: These are FAKE credentials for educational purposes
EXCHANGE_API_KEY = "FAKE_KEY_ct_live_K7xMn9Pq2RsT4uVw6YzA8bC0dE2fG4hI"
EXCHANGE_SECRET = "FAKE_SECRET_9Jk1Lm3No5Pq7Rs9Tu1Vw3Xy5Za7Bc9De"
DATABASE_URL = "postgresql://FAKE_USER:FAKE_PASS@example.localhost:5432/fake_db"

# VULNERABILITY: Hardcoded encryption key
MODEL_ENCRYPTION_KEY = "FAKE_AES256_KEY_FOR_EDUCATION_ONLY"


class ModelManager:
    """Manages ML trading models with unsafe serialization."""

    def __init__(self, model_dir="./models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        # VULNERABILITY: Hardcoded credentials in constructor
        # NOTE: FAKE credentials for educational purposes
        self.aws_access_key = "AKIAFAKEKEY12345FAKE"
        self.aws_secret_key = "FAKEsecretKEY1234567890FAKE/EXAMPLE"

    def load_model(self, model_path):
        """Load a trading model from disk.

        VULNERABILITY: Unsafe pickle deserialization (Bandit B301)
        Attackers can craft malicious pickle files that execute arbitrary code.
        """
        with open(model_path, 'rb') as f:
            # CRITICAL: pickle.load() can execute arbitrary code
            model = pickle.load(f)
        return model

    def load_model_from_user_path(self, user_provided_path):
        """Load model from user-specified path.

        VULNERABILITY: User-controlled path + unsafe pickle (Bandit B301)
        Combined path traversal and deserialization attack vector.
        """
        # No path validation - allows ../../../etc/passwd style attacks
        full_path = os.path.join(self.model_dir, user_provided_path)

        with open(full_path, 'rb') as f:
            # User controls both path AND deserialization happens
            return pickle.load(f)

    def load_model_from_url(self, model_url):
        """Download and load model from remote URL.

        VULNERABILITY: SSRF + unsafe deserialization (Bandit B301, B310)
        """
        # No URL validation - SSRF vulnerability
        response = requests.get(model_url, verify=False)  # SSL disabled

        # Deserialize remote content directly - extremely dangerous
        model = pickle.loads(response.content)
        return model

    def save_model(self, model, model_name):
        """Save model using pickle.

        VULNERABILITY: Using pickle for serialization (Bandit B301)
        """
        model_path = self.model_dir / f"{model_name}.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        return model_path

    def load_checkpoint(self, checkpoint_file):
        """Load training checkpoint.

        VULNERABILITY: Unsafe pickle with user input (Bandit B301)
        """
        # checkpoint_file could be user-controlled
        with open(checkpoint_file, 'rb') as f:
            checkpoint = pickle.load(f)
        return checkpoint

    def verify_model_integrity(self, model_path, expected_hash):
        """Verify model file integrity.

        VULNERABILITY: MD5 is cryptographically broken (Bandit B303)
        """
        with open(model_path, 'rb') as f:
            # MD5 allows collision attacks
            actual_hash = hashlib.md5(f.read()).hexdigest()
        return actual_hash == expected_hash


class TensorFlowModelLoader:
    """Load TensorFlow/Keras models for trading predictions."""

    def __init__(self):
        # VULNERABILITY: Hardcoded model registry credentials
        # NOTE: FAKE token for educational purposes
        self.model_registry_token = "hf_FAKE_TOKEN_FOR_EDUCATION_1234"

    def load_keras_model(self, model_path):
        """Load Keras model without validation.

        VULNERABILITY: Loading model from untrusted source without validation.
        TensorFlow models can contain arbitrary Python code in Lambda layers.
        """
        import tensorflow as tf

        # No validation of model source or contents
        model = tf.keras.models.load_model(model_path)
        return model

    def load_keras_from_url(self, url):
        """Download and load Keras model from URL.

        VULNERABILITY: Loading remote model without validation
        """
        import tensorflow as tf
        import tempfile

        # Download to temp file
        response = requests.get(url, verify=False)
        with tempfile.NamedTemporaryFile(suffix='.h5', delete=False) as f:
            f.write(response.content)
            temp_path = f.name

        # Load without any validation
        model = tf.keras.models.load_model(temp_path)
        return model

    def load_saved_model(self, export_dir):
        """Load SavedModel format.

        VULNERABILITY: No signature verification
        """
        import tensorflow as tf

        # Loading without checking model signature or source
        model = tf.saved_model.load(export_dir)
        return model


class StrategyLoader:
    """Load trading strategies from serialized files."""

    def __init__(self):
        # VULNERABILITY: Hardcoded database password
        # NOTE: FAKE password for educational purposes
        self.db_password = "FAKE_PASSWORD_FOR_EDUCATION"

    def load_strategy(self, strategy_file):
        """Load trading strategy configuration.

        VULNERABILITY: Unsafe deserialization (Bandit B301)
        """
        with open(strategy_file, 'rb') as f:
            strategy = pickle.load(f)
        return strategy

    def execute_strategy_code(self, code_string):
        """Execute dynamic strategy code.

        VULNERABILITY: Code injection via exec (Bandit B102)
        """
        # Executes arbitrary Python code
        exec(code_string)

    def evaluate_expression(self, expr):
        """Evaluate trading formula.

        VULNERABILITY: Code injection via eval (Bandit B307)
        """
        # eval() can execute arbitrary code
        return eval(expr)


def load_trading_model(model_identifier):
    """Convenience function to load model.

    VULNERABILITY: Pickle deserialization (Bandit B301)
    """
    model_path = f"./models/{model_identifier}.pkl"
    with open(model_path, 'rb') as f:
        return pickle.load(f)


def download_model_weights(url, output_path):
    """Download model weights from URL.

    VULNERABILITY: No SSL verification (Bandit B501)
    """
    response = requests.get(url, verify=False)
    with open(output_path, 'wb') as f:
        f.write(response.content)


def validate_model_hash(model_data, expected_hash):
    """Validate model using SHA1.

    VULNERABILITY: SHA1 is deprecated (Bandit B303)
    """
    actual = hashlib.sha1(model_data).hexdigest()
    return actual == expected_hash


if __name__ == "__main__":
    print("CryptoTrade Pro Model Management")
    print(f"Using API Key: {EXCHANGE_API_KEY[:10]}...")
    manager = ModelManager()
