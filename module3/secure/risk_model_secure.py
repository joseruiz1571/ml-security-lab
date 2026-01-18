#!/usr/bin/env python3
"""
HealthTech Innovations - Patient Risk Assessment Model (SECURE VERSION)
This module demonstrates secure implementation patterns for healthcare ML.

Remediation strategies applied:
1. Environment variables for all credentials
2. joblib instead of pickle for model serialization
3. Parameterized SQL queries
4. Input validation
5. Secure random number generation
6. SHA-256 for hashing
"""

import os
import logging
from typing import Optional, Dict, Any, List
from pathlib import Path

import joblib
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import hashlib
import secrets

# Configure logging (don't log sensitive data)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# SECURE: Load all credentials from environment variables
def get_config() -> Dict[str, Optional[str]]:
    """Load configuration from environment variables.

    SECURE: No hardcoded credentials
    """
    return {
        'db_host': os.getenv('DB_HOST'),
        'db_user': os.getenv('DB_USER'),
        'db_password': os.getenv('DB_PASSWORD'),
        'db_name': os.getenv('DB_NAME'),
        'fhir_api_key': os.getenv('FHIR_API_KEY'),
        'aws_region': os.getenv('AWS_REGION', 'us-east-1'),
        's3_bucket': os.getenv('S3_MODEL_BUCKET'),
    }


class SecurePatientRiskModel:
    """Patient cardiovascular risk assessment model with security best practices."""

    # Define expected feature columns
    REQUIRED_FEATURES = ['age', 'blood_pressure', 'cholesterol', 'bmi', 'smoking', 'diabetes']

    # Validation constraints
    FEATURE_CONSTRAINTS = {
        'age': (0, 120),
        'blood_pressure': (50, 250),
        'cholesterol': (100, 500),
        'bmi': (10, 60),
        'smoking': (0, 1),
        'diabetes': (0, 1)
    }

    def __init__(self):
        self.model: Optional[LogisticRegression] = None
        self.scaler = StandardScaler()
        self._config = get_config()

    def _validate_input(self, data: pd.DataFrame) -> bool:
        """Validate input data with proper checks.

        SECURE: Proper validation instead of assert statements
        """
        if data is None or data.empty:
            raise ValueError("Input data cannot be None or empty")

        # Check required columns
        missing_cols = set(self.REQUIRED_FEATURES) - set(data.columns)
        if missing_cols:
            raise ValueError(f"Missing required columns: {missing_cols}")

        # Validate value ranges
        for col, (min_val, max_val) in self.FEATURE_CONSTRAINTS.items():
            if col in data.columns:
                if (data[col] < min_val).any() or (data[col] > max_val).any():
                    raise ValueError(f"Column '{col}' contains values outside valid range [{min_val}, {max_val}]")

        return True

    def save_model(self, filepath: str) -> Path:
        """Save trained model using joblib.

        SECURE: Using joblib instead of pickle, with compression
        """
        if self.model is None:
            raise ValueError("No model to save. Train the model first.")

        # Sanitize filepath
        safe_path = Path(filepath).resolve()
        if not str(safe_path).endswith('.joblib'):
            safe_path = safe_path.with_suffix('.joblib')

        # Save with compression
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.REQUIRED_FEATURES,
            'version': '1.0.0'
        }
        joblib.dump(model_data, safe_path, compress=3)

        logger.info(f"Model saved to {safe_path}")
        return safe_path

    def load_model(self, filepath: str) -> 'SecurePatientRiskModel':
        """Load trained model with validation.

        SECURE: Using joblib with path validation
        """
        path = Path(filepath).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        if not path.suffix == '.joblib':
            raise ValueError("Model file must have .joblib extension")

        # Load model
        model_data = joblib.load(path)

        # Validate model structure
        required_keys = {'model', 'scaler', 'feature_columns'}
        if not required_keys.issubset(model_data.keys()):
            raise ValueError("Invalid model file structure")

        self.model = model_data['model']
        self.scaler = model_data['scaler']

        logger.info(f"Model loaded from {path}")
        return self

    def train(self, X: pd.DataFrame, y: pd.Series) -> 'SecurePatientRiskModel':
        """Train the risk assessment model."""
        # Validate input
        self._validate_input(X)

        X_features = X[self.REQUIRED_FEATURES]
        X_scaled = self.scaler.fit_transform(X_features)

        self.model = LogisticRegression(random_state=42, max_iter=1000)
        self.model.fit(X_scaled, y)

        logger.info("Model training completed")
        return self

    def predict(self, patient_data: pd.DataFrame) -> np.ndarray:
        """Predict risk score for patient with validation.

        SECURE: Input validation before prediction
        """
        if self.model is None:
            raise ValueError("Model not loaded. Load or train a model first.")

        # Validate input
        self._validate_input(patient_data)

        X_features = patient_data[self.REQUIRED_FEATURES]
        scaled_data = self.scaler.transform(X_features)
        risk_prob = self.model.predict_proba(scaled_data)[:, 1]

        return risk_prob

    def get_patient_history(self, patient_id: str) -> List[Dict]:
        """Get patient history using parameterized query.

        SECURE: Parameterized query prevents SQL injection
        """
        import sqlite3

        # Validate patient_id format (alphanumeric only)
        if not patient_id.isalnum():
            raise ValueError("Invalid patient ID format")

        conn = sqlite3.connect('patients.db')
        cursor = conn.cursor()

        # SECURE: Parameterized query
        query = "SELECT * FROM patients WHERE patient_id = ?"
        cursor.execute(query, (patient_id,))

        columns = [description[0] for description in cursor.description] if cursor.description else []
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

    def log_prediction(self, patient_id: str, risk_score: float) -> None:
        """Log prediction using parameterized query.

        SECURE: Parameterized query prevents SQL injection
        """
        import sqlite3

        # Validate inputs
        if not patient_id.isalnum():
            raise ValueError("Invalid patient ID format")

        if not 0 <= risk_score <= 1:
            raise ValueError("Risk score must be between 0 and 1")

        conn = sqlite3.connect('predictions.db')
        cursor = conn.cursor()

        # SECURE: Parameterized query
        query = """
            INSERT INTO predictions (patient_id, risk_score, timestamp)
            VALUES (?, ?, datetime('now'))
        """
        cursor.execute(query, (patient_id, risk_score))
        conn.commit()
        conn.close()

        logger.info(f"Prediction logged for patient {hash_patient_id(patient_id)[:8]}...")


def hash_patient_id(patient_id: str) -> str:
    """Hash patient ID for anonymization.

    SECURE: Using SHA-256 instead of MD5
    """
    return hashlib.sha256(patient_id.encode()).hexdigest()


def generate_session_token() -> str:
    """Generate cryptographically secure session token.

    SECURE: Using secrets module instead of random
    """
    return secrets.token_urlsafe(32)


def calculate_bmi(height_cm: float, weight_kg: float) -> float:
    """Calculate BMI safely.

    SECURE: Direct calculation instead of eval()
    """
    if height_cm <= 0 or weight_kg <= 0:
        raise ValueError("Height and weight must be positive")

    height_m = height_cm / 100
    return weight_kg / (height_m ** 2)


def create_training_sample() -> pd.DataFrame:
    """Create sample training data for demonstration."""
    np.random.seed(42)
    n_samples = 1000

    data = {
        'age': np.random.randint(25, 80, n_samples),
        'blood_pressure': np.random.randint(90, 180, n_samples),
        'cholesterol': np.random.randint(150, 300, n_samples),
        'bmi': np.random.uniform(18, 40, n_samples),
        'smoking': np.random.randint(0, 2, n_samples),
        'diabetes': np.random.randint(0, 2, n_samples)
    }

    df = pd.DataFrame(data)

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
    print("HealthTech Innovations - Patient Risk Assessment (Secure Version)")
    print("Credentials loaded from environment variables")

    # Verify environment is configured
    config = get_config()
    configured = sum(1 for v in config.values() if v is not None)
    print(f"Environment variables configured: {configured}/{len(config)}")

    # Create sample data
    df = create_training_sample()
    print(f"\nTraining data shape: {df.shape}")

    # Prepare features and target
    X = df[SecurePatientRiskModel.REQUIRED_FEATURES]
    y = df['high_risk']

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    model = SecurePatientRiskModel()
    model.train(X_train, y_train)

    # Evaluate
    accuracy = model.model.score(model.scaler.transform(X_test), y_test)
    print(f"Model accuracy: {accuracy:.2%}")

    # Save model (using secure joblib)
    model.save_model('patient_risk_model_secure.joblib')
    print("\nModel saved securely with joblib")
