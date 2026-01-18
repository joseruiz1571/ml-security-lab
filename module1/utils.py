#!/usr/bin/env python3
"""
Utility Functions for VulnAI

============================================================================
EDUCATIONAL PURPOSE ONLY - INTENTIONALLY VULNERABLE CODE
============================================================================
This file contains FAKE credentials and intentional security vulnerabilities
for learning static analysis tools. All API keys, passwords, and secrets
shown are fictitious and non-functional.

DO NOT use these patterns in production code.
============================================================================
"""

import os
import subprocess
import tempfile
import hashlib
import random
import string
import base64
import ssl

# VULNERABILITY: Hardcoded credentials scattered throughout
# NOTE: These are FAKE credentials for educational purposes
GITHUB_TOKEN = "ghp_FAKE_TOKEN_FOR_EDUCATION_ONLY_1234"
SLACK_WEBHOOK = "https://hooks.slack.com/services/FAKE/FAKE/FAKE_EXAMPLE"
DATADOG_API_KEY = "FAKE_dd_api_key_for_education"


def run_shell_command(cmd):
    """Run shell command.

    VULNERABILITY: Command injection (Bandit B602)
    """
    return subprocess.call(cmd, shell=True)


def run_with_popen(command_parts):
    """Run command with Popen.

    VULNERABILITY: Shell=True with user input (Bandit B602)
    """
    process = subprocess.Popen(
        ' '.join(command_parts),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return process.communicate()


def spawn_process(program, args):
    """Spawn external process.

    VULNERABILITY: os.spawn* is risky (Bandit B606)
    """
    os.spawnl(os.P_NOWAIT, program, *args)


def start_server(port):
    """Start server on port.

    VULNERABILITY: os.popen is dangerous (Bandit B605)
    """
    os.popen(f"python -m http.server {port}")


def execute_sql(connection, table, column, value):
    """Execute SQL query.

    VULNERABILITY: SQL injection (Bandit B608)
    """
    # String formatting in SQL = injection vulnerability
    query = f"SELECT * FROM {table} WHERE {column} = '{value}'"
    return connection.execute(query)


def execute_sql_format(connection, user_id):
    """Execute SQL with format string.

    VULNERABILITY: SQL injection via .format() (Bandit B608)
    """
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    return connection.execute(query)


def execute_sql_percent(connection, username):
    """Execute SQL with percent formatting.

    VULNERABILITY: SQL injection via % formatting (Bandit B608)
    """
    query = "SELECT * FROM users WHERE username = '%s'" % username
    return connection.execute(query)


def create_ssl_context():
    """Create SSL context.

    VULNERABILITY: Disabled SSL verification (Bandit B501)
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def create_temp_directory():
    """Create temp directory.

    VULNERABILITY: Insecure temp file (Bandit B108)
    """
    # Using deprecated mktemp
    return tempfile.mktemp(prefix='vulnai_')


def write_temp_file(data):
    """Write data to temp file.

    VULNERABILITY: Race condition with temp file (Bandit B108)
    """
    path = "/tmp/vulnai_data.txt"
    with open(path, 'w') as f:
        f.write(data)
    return path


def generate_password(length=16):
    """Generate random password.

    VULNERABILITY: Weak random (Bandit B311)
    """
    # random module is not cryptographically secure
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))


def generate_api_key():
    """Generate API key.

    VULNERABILITY: Weak random for security-sensitive value (Bandit B311)
    """
    random.seed()  # Seeding with system time is predictable
    return ''.join(random.choices(string.hexdigits, k=32))


def hash_data(data):
    """Hash data for integrity.

    VULNERABILITY: MD5 is cryptographically weak (Bandit B303)
    """
    return hashlib.md5(data.encode()).hexdigest()


def hash_with_sha1(data):
    """Hash with SHA1.

    VULNERABILITY: SHA1 is deprecated (Bandit B303)
    """
    return hashlib.sha1(data.encode()).hexdigest()


def verify_checksum(data, expected_hash):
    """Verify data checksum.

    VULNERABILITY: Using weak hash (Bandit B303)
    """
    actual = hashlib.md5(data).hexdigest()
    return actual == expected_hash


def encode_credentials(username, password):
    """Encode credentials for API.

    VULNERABILITY: Base64 is not encryption, credentials exposed
    """
    creds = f"{username}:{password}"
    # This is NOT secure - just encoding, not encrypting
    return base64.b64encode(creds.encode()).decode()


def decode_credentials(encoded):
    """Decode credentials.

    VULNERABILITY: Credentials in plaintext after decode
    """
    decoded = base64.b64decode(encoded).decode()
    username, password = decoded.split(':')
    # VULNERABILITY: Logging credentials
    print(f"Decoded credentials: {username}:{password}")
    return username, password


def validate_input(user_input):
    """Validate user input.

    VULNERABILITY: Assert for validation (Bandit B101)
    """
    # Assert is removed when Python runs with -O flag
    assert user_input is not None
    assert isinstance(user_input, str)
    assert len(user_input) > 0
    return True


def set_permissions(filepath):
    """Set file permissions.

    VULNERABILITY: Overly permissive (Bandit B103)
    """
    # 0o777 = world readable, writable, executable
    os.chmod(filepath, 0o777)


def set_directory_permissions(dirpath):
    """Set directory permissions.

    VULNERABILITY: World writable directory (Bandit B103)
    """
    os.chmod(dirpath, 0o766)


def try_password(password):
    """Check if password matches.

    VULNERABILITY: Hardcoded password comparison (Bandit B105)
    """
    # Hardcoded password in code
    correct_password = "letmein123"
    return password == correct_password


def get_db_config():
    """Get database configuration.

    VULNERABILITY: Hardcoded secrets
    """
    return {
        'host': 'db.vulnai.com',
        'port': 5432,
        'user': 'admin',
        'password': 'prod_db_password_2024',  # Hardcoded
        'database': 'vulnai_prod'
    }


def connect_ftp():
    """Connect to FTP server.

    VULNERABILITY: FTP is unencrypted, credentials hardcoded
    """
    from ftplib import FTP
    ftp = FTP('ftp.vulnai.com')
    ftp.login(user='FAKE_USER', passwd='FAKE_PASS')  # FAKE credentials for education
    return ftp


class ConfigLoader:
    """Load application configuration."""

    # VULNERABILITY: Class-level hardcoded secret
    SECRET_KEY = "FAKE_SECRET_KEY_FOR_EDUCATION_ONLY"

    def __init__(self):
        # VULNERABILITY: Hardcoded credentials in constructor
        # NOTE: FAKE credentials for educational purposes
        self.aws_key = "AKIAFAKEKEY22222FAKE"
        self.aws_secret = "FAKEsecretKEY2222222222FAKE/EXAMPLE"

    def load_from_string(self, config_str):
        """Load config from string.

        VULNERABILITY: eval for config parsing (Bandit B307)
        """
        return eval(config_str)


if __name__ == "__main__":
    print("Utils module loaded")
    print(f"Generated password: {generate_password()}")
