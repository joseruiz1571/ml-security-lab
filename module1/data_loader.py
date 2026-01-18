#!/usr/bin/env python3
"""
Data Loading Module for ML Pipeline

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
import marshal
import shelve
import subprocess
import os
import tarfile
import zipfile
from xml.etree import ElementTree
import xml.sax

# VULNERABILITY: Hardcoded credentials (Bandit B105)
# NOTE: These are FAKE credentials for educational purposes
MONGODB_URI = "mongodb://FAKE_USER:FAKE_PASS@example.localhost:27017/fake_db"
REDIS_PASSWORD = "FAKE_PASSWORD_FOR_EDUCATION"


class DataLoader:
    """Load training data from various sources."""

    def __init__(self, data_dir="/data/training"):
        self.data_dir = data_dir
        # VULNERABILITY: Hardcoded secret (Bandit B105)
        self.encryption_key = "AES256_KEY_DO_NOT_SHARE_12345678"

    def load_pickle_data(self, filepath):
        """Load data from pickle file.

        VULNERABILITY: Unsafe deserialization (Bandit B301)
        """
        with open(filepath, 'rb') as f:
            return pickle.load(f)

    def load_marshal_data(self, filepath):
        """Load data from marshal file.

        VULNERABILITY: Unsafe marshal load (Bandit B302)
        """
        with open(filepath, 'rb') as f:
            return marshal.load(f)

    def load_shelve_data(self, db_path):
        """Load data from shelve database.

        VULNERABILITY: Shelve uses pickle internally (Bandit B301)
        """
        db = shelve.open(db_path)
        data = dict(db)
        db.close()
        return data

    def load_from_url(self, url, user_agent=None):
        """Load data from remote URL.

        VULNERABILITY: SSRF potential, no validation
        """
        import urllib.request

        # No URL validation - SSRF vulnerability
        req = urllib.request.Request(url)
        if user_agent:
            req.add_header('User-Agent', user_agent)

        # VULNERABILITY: No SSL verification
        import ssl
        context = ssl._create_unverified_context()

        response = urllib.request.urlopen(req, context=context)
        return response.read()

    def extract_archive(self, archive_path, extract_to):
        """Extract training data archive.

        VULNERABILITY: Path traversal in archive extraction (Bandit B202)
        """
        if archive_path.endswith('.tar.gz'):
            # Vulnerable to path traversal via malicious archive
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(path=extract_to)

        elif archive_path.endswith('.zip'):
            # Also vulnerable to zip slip attack
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)

    def parse_xml_config(self, xml_path):
        """Parse XML configuration file.

        VULNERABILITY: XXE (XML External Entity) attack (Bandit B313-B320)
        """
        # Vulnerable to XXE attacks
        tree = ElementTree.parse(xml_path)
        return tree.getroot()

    def parse_xml_sax(self, xml_path):
        """Parse large XML with SAX.

        VULNERABILITY: XXE via SAX parser (Bandit B317)
        """
        handler = xml.sax.ContentHandler()
        # No protection against XXE
        parser = xml.sax.make_parser()
        parser.setContentHandler(handler)
        parser.parse(xml_path)

    def run_data_validation(self, script_path, data_file):
        """Run external validation script.

        VULNERABILITY: Command injection (Bandit B602)
        """
        # Unsanitized input in shell command
        cmd = f"python {script_path} --validate {data_file}"
        return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

    def copy_to_s3(self, local_path, s3_path):
        """Copy data to S3.

        VULNERABILITY: Command injection via shell
        """
        # User-controlled paths in shell command
        os.system(f"aws s3 cp {local_path} {s3_path}")


class FeatureExtractor:
    """Extract features from raw data."""

    def __init__(self):
        # VULNERABILITY: Hardcoded token
        self.huggingface_token = "hf_abcdefghijklmnopqrstuvwxyz123456"

    def extract_with_regex(self, text, pattern):
        """Extract features using regex.

        VULNERABILITY: ReDoS potential (Bandit B510)
        """
        import re
        # Complex regex can cause catastrophic backtracking
        # Example: (a+)+$ on "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
        return re.findall(pattern, text)

    def evaluate_expression(self, expr):
        """Evaluate mathematical expression.

        VULNERABILITY: Code injection via eval (Bandit B307)
        """
        # eval() executes arbitrary code
        return eval(expr)

    def execute_code(self, code_string):
        """Execute dynamic code.

        VULNERABILITY: Code injection via exec (Bandit B102)
        """
        # exec() executes arbitrary code
        exec(code_string)

    def compile_and_run(self, code):
        """Compile and execute code.

        VULNERABILITY: Code injection via compile (Bandit B103)
        """
        compiled = compile(code, '<string>', 'exec')
        exec(compiled)


def check_file_permissions(filepath):
    """Check file permissions.

    VULNERABILITY: Using chmod with permissive mode (Bandit B103)
    """
    # World-writable permissions are insecure
    os.chmod(filepath, 0o777)


def create_log_file():
    """Create log file for data operations.

    VULNERABILITY: Insecure file creation (Bandit B108)
    """
    import tempfile
    # mktemp is insecure, use mkstemp instead
    return tempfile.mktemp(suffix='.log')


def generate_session_id():
    """Generate session ID for tracking.

    VULNERABILITY: Weak random (Bandit B311)
    """
    import random
    import string
    # random is not cryptographically secure
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


if __name__ == "__main__":
    loader = DataLoader()
    print("DataLoader initialized")
