#!/usr/bin/env python3
"""
HealthTech Innovations - Patient Risk Assessment Model

============================================================================
EDUCATIONAL PURPOSE ONLY - INTENTIONALLY VULNERABLE CODE
============================================================================
This file contains FAKE credentials and intentional security vulnerabilities
for learning static analysis tools. All API keys, passwords, and secrets
shown are fictitious and non-functional.

This model predicts cardiovascular disease risk based on patient demographics
and medical metrics. It failed its security audit and requires remediation.

DO NOT use these patterns in production code.
============================================================================
"""

import pickle
import os
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import sqlite3

# VULNERABILITY: Hardcoded database credentials (Bandit B105)
# NOTE: These are FAKE credentials for educational purposes
DB_HOST = "example.localhost"
DB_USER = "FAKE_USER"
DB_PASSWORD = "FAKE_PASSWORD_FOR_EDUCATION"
DB_NAME = "fake_database"

# VULNERABILITY: Hardcoded API keys
# NOTE: FAKE keys for educational purposes
FHIR_API_KEY = "FAKE_fhir_key_Xk9Mn2Pq5RsT8uVw1YzA"
EHR_INTEGRATION_TOKEN = "FAKE_ehr_token_AbCdEfGhIjKlMnOp"

# VULNERABILITY: Hardcoded AWS credentials for model storage
# NOTE: FAKE credentials for educational purposes
AWS_ACCESS_KEY = "AKIAFAKEKEY11111FAKE"
AWS_SECRET_KEY = "FAKEsecretKEY1111111111FAKE/EXAMPLE"
S3_BUCKET = "fake-example-bucket"

# VULNERABILITY: Hardcoded encryption key for PHI
# NOTE: FAKE key for educational purposes
PHI_ENCRYPTION_KEY = "FAKE_AES256_KEY_FOR_EDUCATION_ONLY"


class PatientRiskModel:
    """Patient cardiovascular risk assessment model."""

    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        # VULNERABILITY: Hardcoded connection string
        self.db_connection = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

    def load_patient_data(self, data_path):
        """Load patient data from file.

        VULNERABILITY: Unsafe pickle deserialization (Bandit B301)
        """
        with open(data_path, 'rb') as f:
            # CRITICAL: pickle.load can execute arbitrary code
            data = pickle.load(f)
        return data

    def save_model(self, filepath):
        """Save trained model to file.

        VULNERABILITY: Using pickle for model serialization (Bandit B301)
        """
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler
            }, f)
        print(f"Model saved to {filepath}")

    def load_model(self, filepath):
        """Load trained model from file.

        VULNERABILITY: Unsafe pickle deserialization (Bandit B301)
        """
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        self.model = data['model']
        self.scaler = data['scaler']
        return self

    def train(self, X, y):
        """Train the risk assessment model."""
        X_scaled = self.scaler.fit_transform(X)
        self.model = LogisticRegression(random_state=42, max_iter=1000)
        self.model.fit(X_scaled, y)
        return self

    def predict(self, patient_data):
        """Predict risk score for patient.

        VULNERABILITY: No input validation
        """
        # No validation of input data
        scaled_data = self.scaler.transform(patient_data)
        risk_prob = self.model.predict_proba(scaled_data)[:, 1]
        return risk_prob

    def get_patient_history(self, patient_id):
        """Get patient history from database.

        VULNERABILITY: SQL injection (Bandit B608)
        """
        conn = sqlite3.connect('patients.db')
        cursor = conn.cursor()

        # String formatting in SQL - vulnerable to injection
        query = f"SELECT * FROM patients WHERE patient_id = '{patient_id}'"
        cursor.execute(query)
        return cursor.fetchall()

    def log_prediction(self, patient_id, risk_score):
        """Log prediction to database.

        VULNERABILITY: SQL injection (Bandit B608)
        """
        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()

        query = f"""
            INSERT INTO predictions (patient_id, risk_score, timestamp)
            VALUES ('{patient_id}', {risk_score}, datetime('now'))
        """
        cursor.execute(query)
        conn.commit()


def load_model_from_s3(model_key):
    """Download model from S3.

    VULNERABILITY: Hardcoded credentials + unsafe deserialization
    """
    import boto3

    # Using hardcoded credentials (should use IAM roles)
    s3 = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )

    # Download to temp file
    local_path = f"/tmp/{model_key}"
    s3.download_file(S3_BUCKET, model_key, local_path)

    # Unsafe deserialization
    with open(local_path, 'rb') as f:
        model = pickle.load(f)
    return model


def validate_patient_data(data):
    """Validate patient data.

    VULNERABILITY: Using assert for validation (Bandit B101)
    """
    # Assert statements are removed in optimized bytecode (-O flag)
    assert data is not None, "Data cannot be None"
    assert 'age' in data, "Age is required"
    assert data['age'] > 0, "Age must be positive"
    return True


def calculate_bmi(height_formula, weight):
    """Calculate BMI from formula.

    VULNERABILITY: Code injection via eval (Bandit B307)
    """
    # User-provided formula executed directly
    height = eval(height_formula)
    return weight / (height ** 2)


def run_analysis_script(script_path):
    """Run external analysis script.

    VULNERABILITY: Command injection (Bandit B602)
    """
    import subprocess
    cmd = f"python {script_path}"
    subprocess.call(cmd, shell=True)


def hash_patient_id(patient_id):
    """Hash patient ID for anonymization.

    VULNERABILITY: Weak hash algorithm (Bandit B303)
    """
    import hashlib
    # MD5 is not suitable for security purposes
    return hashlib.md5(patient_id.encode()).hexdigest()


def generate_session_token():
    """Generate session token.

    VULNERABILITY: Weak random (Bandit B311)
    """
    import random
    import string
    # random module is not cryptographically secure
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


def create_training_sample():
    """Create sample training data for demonstration."""
    np.random.seed(42)
    n_samples = 1000

    # Generate synthetic patient data
    data = {
        'age': np.random.randint(25, 80, n_samples),
        'blood_pressure': np.random.randint(90, 180, n_samples),
        'cholesterol': np.random.randint(150, 300, n_samples),
        'bmi': np.random.uniform(18, 40, n_samples),
        'smoking': np.random.randint(0, 2, n_samples),
        'diabetes': np.random.randint(0, 2, n_samples)
    }

    df = pd.DataFrame(data)

    # Generate risk labels based on features
    risk_score = (
        (df['age'] > 55).astype(int) * 0.3 +
        (df['blood_pressure'] > 140).astype(int) * 0.25 +
        (df['cholesterol'] > 240).astype(int) * 0.2 +
        (df['bmi'] > 30).astype(int) * 0.15 +
        df['smoking'] * 0.05 +
        df['diabetes'] * 0.05 +
        np.random.uniform(0, 0.2, n_samples)
    )

    df['high_risk'] = (risk_score > 0.5).astype(int)

    return df


if __name__ == "__main__":
    print("HealthTech Innovations - Patient Risk Assessment")
    print(f"Database: {DB_HOST}")
    print(f"Using API Key: {FHIR_API_KEY[:10]}...")

    # Create sample data
    df = create_training_sample()
    print(f"\nTraining data shape: {df.shape}")

    # Prepare features and target
    feature_cols = ['age', 'blood_pressure', 'cholesterol', 'bmi', 'smoking', 'diabetes']
    X = df[feature_cols]
    y = df['high_risk']

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    model = PatientRiskModel()
    model.train(X_train, y_train)

    # Evaluate
    accuracy = model.model.score(model.scaler.transform(X_test), y_test)
    print(f"Model accuracy: {accuracy:.2%}")

    # Save model (using vulnerable pickle)
    model.save_model('patient_risk_model.pkl')
    print("\nWARNING: Model saved with pickle - vulnerable to deserialization attacks")
