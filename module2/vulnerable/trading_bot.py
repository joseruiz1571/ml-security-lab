#!/usr/bin/env python3
"""
CryptoTrade Pro - Automated Trading Bot

============================================================================
EDUCATIONAL PURPOSE ONLY - INTENTIONALLY VULNERABLE CODE
============================================================================
This file contains FAKE credentials and intentional security vulnerabilities
for learning static analysis tools. All API keys, passwords, wallet keys,
and secrets shown are fictitious and non-functional.

DO NOT use these patterns in production code.
============================================================================
"""

import pickle
import subprocess
import os
import sqlite3
import logging
from datetime import datetime

# VULNERABILITY: Hardcoded exchange credentials (Bandit B105)
# NOTE: These are FAKE credentials for educational purposes
BINANCE_API_KEY = "FAKE_bnc_live_Xk9Mn2Pq5RsT8uVw1YzA"
BINANCE_SECRET = "FAKE_bnc_secret_2Lm4No6Pq8Rs0Tu2Vw4Xy"
COINBASE_API_KEY = "FAKE_cb_prod_9Jk1Lm3No5Pq7Rs9Tu1Vw"
KRAKEN_API_KEY = "FAKE_kraken_key_AbCdEfGhIjKlMnOp"

# VULNERABILITY: Hardcoded wallet private key - CRITICAL
# NOTE: This is a FAKE private key for educational purposes - NOT A REAL WALLET
WALLET_PRIVATE_KEY = "0xFAKE0000000000000000000000000000000000000000000000000000FAKE1234"

# VULNERABILITY: Debug mode exposing sensitive data
DEBUG_MODE = True

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TradingBot:
    """Automated cryptocurrency trading bot."""

    def __init__(self):
        # VULNERABILITY: Storing secrets in instance variables
        self.api_key = BINANCE_API_KEY
        self.api_secret = BINANCE_SECRET
        self.wallet_key = WALLET_PRIVATE_KEY

        # VULNERABILITY: Hardcoded database credentials
        # NOTE: FAKE credentials for educational purposes
        self.db_connection_string = "mysql://FAKE_USER:FAKE_PASS@example.localhost/fake_db"

    def load_trading_strategy(self, strategy_path):
        """Load strategy from pickle file.

        VULNERABILITY: Unsafe pickle deserialization (Bandit B301)
        """
        with open(strategy_path, 'rb') as f:
            strategy = pickle.load(f)

        # VULNERABILITY: Logging sensitive strategy data
        logger.debug(f"Loaded strategy: {strategy}")
        return strategy

    def execute_trade(self, trade_command):
        """Execute trading command.

        VULNERABILITY: Command injection (Bandit B602)
        """
        # User-controlled input in shell command
        cmd = f"./trade_executor.sh {trade_command}"
        result = subprocess.call(cmd, shell=True)
        return result

    def run_backtest(self, script_name, params):
        """Run backtesting script.

        VULNERABILITY: Command injection via subprocess (Bandit B602)
        """
        command = f"python backtest/{script_name} --params '{params}'"
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return process.communicate()

    def log_trade(self, trade_data):
        """Log trade to database.

        VULNERABILITY: SQL injection (Bandit B608)
        """
        conn = sqlite3.connect('trades.db')
        cursor = conn.cursor()

        # String formatting in SQL query - SQL injection
        query = f"""
            INSERT INTO trades (symbol, amount, price, timestamp)
            VALUES ('{trade_data['symbol']}', {trade_data['amount']},
                    {trade_data['price']}, '{trade_data['timestamp']}')
        """
        cursor.execute(query)
        conn.commit()
        conn.close()

    def get_trade_history(self, user_id):
        """Get trade history for user.

        VULNERABILITY: SQL injection (Bandit B608)
        """
        conn = sqlite3.connect('trades.db')
        cursor = conn.cursor()

        # Vulnerable to SQL injection
        query = "SELECT * FROM trades WHERE user_id = '%s'" % user_id
        cursor.execute(query)
        return cursor.fetchall()

    def calculate_profit(self, expression):
        """Calculate profit from expression.

        VULNERABILITY: Code injection via eval (Bandit B307)
        """
        # User-provided expression evaluated directly
        return eval(expression)


class PortfolioManager:
    """Manage trading portfolio."""

    def __init__(self):
        # VULNERABILITY: Hardcoded AWS credentials
        # NOTE: FAKE credentials for educational purposes
        self.s3_access_key = "AKIAFAKEKEY67890FAKE"
        self.s3_secret_key = "FAKEsecretKEY0987654321FAKE/EXAMPLE"
        self.s3_bucket = "fake-example-bucket"

    def load_portfolio(self, portfolio_file):
        """Load portfolio from file.

        VULNERABILITY: Unsafe pickle (Bandit B301)
        """
        with open(portfolio_file, 'rb') as f:
            return pickle.load(f)

    def save_portfolio(self, portfolio, filepath):
        """Save portfolio to file.

        VULNERABILITY: Insecure file permissions (Bandit B103)
        """
        with open(filepath, 'wb') as f:
            pickle.dump(portfolio, f)

        # World-writable permissions
        os.chmod(filepath, 0o777)

    def sync_to_cloud(self, local_path, remote_path):
        """Sync portfolio to S3.

        VULNERABILITY: Command injection (Bandit B602)
        """
        # User-controlled paths in shell command
        os.system(f"aws s3 cp {local_path} s3://{self.s3_bucket}/{remote_path}")


class RiskAnalyzer:
    """Analyze trading risk."""

    def __init__(self):
        # VULNERABILITY: Hardcoded API token
        # NOTE: FAKE token for educational purposes
        self.risk_api_token = "FAKE_TOKEN_FOR_EDUCATION_ONLY"

    def load_risk_model(self, model_url):
        """Load risk model from URL.

        VULNERABILITY: SSRF + unsafe deserialization
        """
        import requests

        # No URL validation, no SSL verification
        response = requests.get(model_url, verify=False)

        # Deserialize untrusted remote data
        return pickle.loads(response.content)

    def analyze_with_script(self, script_content):
        """Run risk analysis script.

        VULNERABILITY: Code injection via exec (Bandit B102)
        """
        exec(script_content)


def connect_to_exchange():
    """Connect to cryptocurrency exchange.

    VULNERABILITY: Exposing credentials in logs
    """
    logger.info(f"Connecting with API key: {BINANCE_API_KEY}")
    logger.debug(f"Using secret: {BINANCE_SECRET}")
    return True


def create_temp_trade_file(trade_data):
    """Create temporary file for trade.

    VULNERABILITY: Insecure temp file (Bandit B108)
    """
    import tempfile

    # Predictable temp file path
    temp_path = "/tmp/trade_data.pkl"
    with open(temp_path, 'wb') as f:
        pickle.dump(trade_data, f)
    return temp_path


def generate_trade_id():
    """Generate unique trade ID.

    VULNERABILITY: Weak random (Bandit B311)
    """
    import random
    import string

    # Not cryptographically secure
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


def start_trading_server():
    """Start the trading server.

    VULNERABILITY: Binding to all interfaces (Bandit B104)
    """
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Exposes to all network interfaces
    sock.bind(('0.0.0.0', 8888))
    sock.listen(5)
    return sock


if __name__ == "__main__":
    print("CryptoTrade Pro Trading Bot")
    print(f"Debug Mode: {DEBUG_MODE}")

    bot = TradingBot()
    print("Bot initialized")
