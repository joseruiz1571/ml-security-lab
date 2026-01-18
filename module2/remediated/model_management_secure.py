#!/usr/bin/env python3
"""
CryptoTrade Pro - Model Management Module (SECURE VERSION)
This module demonstrates secure alternatives to the vulnerable patterns.

Remediation strategies applied:
1. Environment variables for credentials
2. joblib/safetensors instead of pickle
3. Model signature verification
4. Input validation and sanitization
"""

import os
import json
import hashlib
import hmac
import logging
from pathlib import Path
from typing import Optional, Any
import joblib  # Safer than raw pickle, but still verify sources

# SECURE: Load credentials from environment variables
EXCHANGE_API_KEY = os.getenv("EXCHANGE_API_KEY")
EXCHANGE_SECRET = os.getenv("EXCHANGE_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")

# Validate required environment variables
if not all([EXCHANGE_API_KEY, EXCHANGE_SECRET]):
    logging.warning("Exchange credentials not configured. Set EXCHANGE_API_KEY and EXCHANGE_SECRET.")

# SECURE: Model signing key from environment
MODEL_SIGNING_KEY = os.getenv("MODEL_SIGNING_KEY", "").encode()


class SecureModelManager:
    """Manages ML trading models with secure serialization."""

    # Allowed model file extensions
    ALLOWED_EXTENSIONS = {'.joblib', '.json', '.safetensors', '.onnx'}

    # Maximum file size (100MB)
    MAX_MODEL_SIZE = 100 * 1024 * 1024

    def __init__(self, model_dir: str = "./models"):
        self.model_dir = Path(model_dir).resolve()  # Resolve to absolute path
        self.model_dir.mkdir(exist_ok=True)

        # SECURE: Load AWS credentials from environment
        self.aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")

    def _validate_path(self, filepath: str) -> Path:
        """Validate and sanitize file path to prevent path traversal.

        SECURE: Prevents ../../../etc/passwd style attacks
        """
        # Convert to Path and resolve
        requested_path = Path(filepath)

        # If relative, join with model_dir
        if not requested_path.is_absolute():
            full_path = (self.model_dir / requested_path).resolve()
        else:
            full_path = requested_path.resolve()

        # Ensure path is within allowed directory
        try:
            full_path.relative_to(self.model_dir)
        except ValueError:
            raise ValueError(f"Path traversal attempt detected: {filepath}")

        # Validate extension
        if full_path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            raise ValueError(f"Invalid file extension: {full_path.suffix}")

        return full_path

    def _verify_model_signature(self, model_path: Path) -> bool:
        """Verify model file signature before loading.

        SECURE: Ensures model hasn't been tampered with
        """
        signature_path = model_path.with_suffix(model_path.suffix + '.sig')

        if not signature_path.exists():
            logging.warning(f"No signature file found for {model_path}")
            return False

        if not MODEL_SIGNING_KEY:
            logging.error("MODEL_SIGNING_KEY not configured")
            return False

        # Read model content
        with open(model_path, 'rb') as f:
            model_content = f.read()

        # Read expected signature
        with open(signature_path, 'r') as f:
            expected_signature = f.read().strip()

        # Compute HMAC-SHA256 signature
        computed_signature = hmac.new(
            MODEL_SIGNING_KEY,
            model_content,
            hashlib.sha256
        ).hexdigest()

        # SECURE: Constant-time comparison prevents timing attacks
        return hmac.compare_digest(computed_signature, expected_signature)

    def load_model_safe(self, model_path: str, verify_signature: bool = True) -> Any:
        """Load a trading model with security validations.

        SECURE VERSION:
        - Path validation prevents traversal
        - Signature verification ensures integrity
        - Size limits prevent DoS
        - Uses joblib instead of raw pickle
        """
        # Validate path
        safe_path = self._validate_path(model_path)

        if not safe_path.exists():
            raise FileNotFoundError(f"Model not found: {safe_path}")

        # Check file size
        if safe_path.stat().st_size > self.MAX_MODEL_SIZE:
            raise ValueError(f"Model file exceeds maximum size of {self.MAX_MODEL_SIZE} bytes")

        # Verify signature (recommended for production)
        if verify_signature:
            if not self._verify_model_signature(safe_path):
                raise ValueError("Model signature verification failed")

        # Load using joblib (safer than pickle, but still verify source)
        # For maximum security, use ONNX or safetensors format
        model = joblib.load(safe_path)

        logging.info(f"Model loaded successfully: {safe_path.name}")
        return model

    def save_model_safe(self, model: Any, model_name: str) -> Path:
        """Save model with signature for integrity verification.

        SECURE: Creates signature file for later verification
        """
        # Sanitize model name
        safe_name = "".join(c for c in model_name if c.isalnum() or c in '-_')
        model_path = self.model_dir / f"{safe_name}.joblib"

        # Save model using joblib with compression
        joblib.dump(model, model_path, compress=3)

        # Generate and save signature
        if MODEL_SIGNING_KEY:
            with open(model_path, 'rb') as f:
                model_content = f.read()

            signature = hmac.new(
                MODEL_SIGNING_KEY,
                model_content,
                hashlib.sha256
            ).hexdigest()

            signature_path = model_path.with_suffix('.joblib.sig')
            with open(signature_path, 'w') as f:
                f.write(signature)

            logging.info(f"Model saved with signature: {model_path}")
        else:
            logging.warning("Model saved without signature (MODEL_SIGNING_KEY not set)")

        return model_path


class SecureTensorFlowModelLoader:
    """Load TensorFlow/Keras models securely."""

    def __init__(self):
        # SECURE: Token from environment
        self.model_registry_token = os.getenv("MODEL_REGISTRY_TOKEN")

    def load_keras_model_safe(self, model_path: str, allow_custom_objects: bool = False):
        """Load Keras model with security options.

        SECURE VERSION:
        - Validates model path
        - Disables custom objects by default (prevents code execution)
        - Uses safe_mode when available (TF 2.13+)
        """
        import tensorflow as tf

        # Validate path exists
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        # Load with safety options
        try:
            # TensorFlow 2.13+ supports safe_mode
            model = tf.keras.models.load_model(
                model_path,
                compile=False,  # Don't compile - safer
                safe_mode=True  # Blocks arbitrary code execution
            )
        except TypeError:
            # Older TensorFlow versions
            if allow_custom_objects:
                logging.warning("Loading model with custom objects enabled - ensure source is trusted")
                model = tf.keras.models.load_model(model_path)
            else:
                model = tf.keras.models.load_model(
                    model_path,
                    compile=False,
                    custom_objects=None  # Disable custom objects
                )

        return model


def get_database_connection():
    """Get database connection using environment variables.

    SECURE: No hardcoded credentials
    """
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise EnvironmentError("DATABASE_URL environment variable not set")

    # Use the URL from environment (should be set securely)
    return db_url


# Example .env.example file content for reference
ENV_EXAMPLE = """
# CryptoTrade Pro Environment Variables
# Copy this file to .env and fill in your values

EXCHANGE_API_KEY=your_api_key_here
EXCHANGE_SECRET=your_secret_here
DATABASE_URL=postgresql://user:password@localhost:5432/trading
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
MODEL_SIGNING_KEY=your_32_byte_signing_key_here
MODEL_REGISTRY_TOKEN=your_registry_token
"""


if __name__ == "__main__":
    print("CryptoTrade Pro Model Management (Secure Version)")
    print("Credentials loaded from environment variables")

    # Demonstrate secure usage
    manager = SecureModelManager()
    print(f"Model directory: {manager.model_dir}")
