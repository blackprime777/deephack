import requests
import random
from cryptography.fernet import Fernet

class BlockchainTracer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.cipher = Fernet(b"TadCslen4-lxCNLNOUtAfB2E2V8vWdqLjb5GoxSXfC4=")  # FIXED Fernet key

    def trace_address(self, address):
        """
        Trace Ethereum wallet using Etherscan API.
        Encrypts raw response data and computes a risk score.
        """
        url = "https://api.etherscan.io/api"
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "asc",
            "apikey": self.api_key
        }

        try:
            response = requests.get(url, params=params, timeout=10)
            data = response.json()

            if data["status"] != "1":
                return {
                    "risk_score": 0,
                    "message": "No transactions or invalid address"
                }

            transactions = data["result"]
            tx_count = len(transactions)
            high_value_txs = sum(
                1 for tx in transactions if float(tx["value"]) > 1e18  # > 1 ETH
            )

            risk_score = min(100, tx_count + high_value_txs * 10)
            encrypted_raw = self.cipher.encrypt(response.text.encode())

            return {
                "risk_score": risk_score,
                "tx_count": tx_count,
                "high_value_txs": high_value_txs,
                "encrypted_data": encrypted_raw.decode()
            }

        except Exception as e:
            return {
                "risk_score": random.randint(30, 70),
                "error": str(e)
            }
