
import hashlib
import json
import time
import uuid
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


VERSION = "GLOBALCOIN VERSION 4"


def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def valid_address(address):
    try:
        return (
            isinstance(address, str)
            and len(address) == 64
            and len(bytes.fromhex(address)) == 32
        )
    except (ValueError, TypeError):
        return False


class Wallet:
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    @classmethod
    def from_private_key(cls, private_bytes):
        wallet = cls.__new__(cls)
        wallet.private_key = Ed25519PrivateKey.from_private_bytes(
            private_bytes
        )
        wallet.public_key = wallet.private_key.public_key()
        return wallet

    def get_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

    def get_address(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

    def sign_transaction(self, transaction):
        return self.private_key.sign(
            canonical_json(transaction)
        ).hex()

    @staticmethod
    def verify_signature(transaction, signature):
        try:
            sender = transaction["sender"]

            if not valid_address(sender):
                return False

            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(sender)
            )

            public_key.verify(
                bytes.fromhex(signature),
                canonical_json(transaction)
            )
            return True

        except Exception:
            return False

    def save(self, filename, password):
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Password must contain at least 8 characters")

        salt = os.urandom(16)
        nonce = os.urandom(12)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000
        )

        key = kdf.derive(password.encode("utf-8"))

        encrypted = AESGCM(key).encrypt(
            nonce,
            bytes.fromhex(self.get_private_key()),
            None
        )

        data = {
            "version": 1,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "encrypted_key": encrypted.hex()
        }

        with open(filename, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

    @classmethod
    def load(cls, filename, password):
        with open(filename, "r", encoding="utf-8") as file:
            data = json.load(file)

        if data.get("version") != 1:
            raise ValueError("Unsupported wallet version")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes.fromhex(data["salt"]),
            iterations=600000
        )

        key = kdf.derive(password.encode("utf-8"))

        private_bytes = AESGCM(key).decrypt(
            bytes.fromhex(data["nonce"]),
            bytes.fromhex(data["encrypted_key"]),
            None
        )

        return cls.from_private_key(private_bytes)


class Blockchain:
    def __init__(self, difficulty=3, initial_balances=None):
        if (
            isinstance(difficulty, bool)
            or not isinstance(difficulty, int)
            or not 1 <= difficulty <= 6
        ):
            raise ValueError("Difficulty must be between 1 and 6")

        self.difficulty = difficulty
        self.chain = []
        self.pending_transactions = []

        allocations = initial_balances or {}

        for address, amount in allocations.items():
            if not valid_address(address):
                raise ValueError("Invalid allocation address")

            if (
                isinstance(amount, bool)
                or not isinstance(amount, int)
                or amount <= 0
            ):
                raise ValueError("Invalid initial balance")

        self.create_genesis_block(allocations)

    def calculate_hash(self, block):
        data = {
            "index": block["index"],
            "timestamp": block["timestamp"],
            "transactions": block["transactions"],
            "previous_hash": block["previous_hash"],
            "nonce": block["nonce"],
            "allocations": block["allocations"]
        }

        return hashlib.sha256(canonical_json(data)).hexdigest()

    def mine_block(self, block):
        target = "0" * self.difficulty

        while True:
            block_hash = self.calculate_hash(block)

            if block_hash.startswith(target):
                block["hash"] = block_hash
                return block

            block["nonce"] += 1

    def create_genesis_block(self, allocations):
        genesis = {
            "index": 0,
            "timestamp": int(time.time()),
            "transactions": [],
            "previous_hash": "0",
            "nonce": 0,
            "allocations": allocations
        }

        self.chain.append(self.mine_block(genesis))

    def get_balances(self, include_pending=False):
        balances = {}

        for address, amount in self.chain[0]["allocations"].items():
            balances[address] = amount

        for block in self.chain[1:]:
            for transaction in block["transactions"]:
                sender = transaction["sender"]
                recipient = transaction["recipient"]
                amount = transaction["amount"]

                balances[sender] = balances.get(sender, 0) - amount
                balances[recipient] = balances.get(recipient, 0) + amount

        if include_pending:
            for transaction in self.pending_transactions:
                sender = transaction["sender"]
                recipient = transaction["recipient"]
                amount = transaction["amount"]

                balances[sender] = balances.get(sender, 0) - amount
                balances[recipient] = balances.get(recipient, 0) + amount

        return balances

    def get_balance(self, address, include_pending=False):
        if not valid_address(address):
            raise ValueError("Invalid wallet address")

        return self.get_balances(include_pending).get(address, 0)

    def add_transaction(self, wallet, recipient, amount):
        if not isinstance(wallet, Wallet):
            raise ValueError("Invalid wallet")

        if not valid_address(recipient):
            raise ValueError("Invalid recipient address")

        if (
            isinstance(amount, bool)
            or not isinstance(amount, int)
            or amount <= 0
        ):
            raise ValueError("Amount must be a positive integer")

        sender = wallet.get_address()

        if sender == recipient:
            raise ValueError("Cannot send to the same wallet")

        if self.get_balance(sender, True) < amount:
            raise ValueError("Insufficient balance")

        transaction = {
            "transaction_id": str(uuid.uuid4()),
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "timestamp": int(time.time())
        }

        signature = wallet.sign_transaction(transaction)

        if not Wallet.verify_signature(transaction, signature):
            raise ValueError("Signature verification failed")

        transaction["signature"] = signature
        self.pending_transactions.append(transaction)

        return transaction["transaction_id"]

    def mine_pending_transactions(self):
        if not self.pending_transactions:
            return None

        block = {
            "index": len(self.chain),
            "timestamp": int(time.time()),
            "transactions": self.pending_transactions.copy(),
            "previous_hash": self.chain[-1]["hash"],
            "nonce": 0,
            "allocations": {}
        }

        mined_block = self.mine_block(block)

        self.chain.append(mined_block)
        self.pending_transactions = []

        return mined_block

    def is_chain_valid(self):
        if not self.chain:
            return False

        balances = {}
        transaction_ids = set()

        for index, block in enumerate(self.chain):
            try:
                if set(block.keys()) != {
                    "index", "timestamp", "transactions",
                    "previous_hash", "nonce", "allocations", "hash"
                }:
                    return False

                if block["index"] != index:
                    return False

                if (
                    isinstance(block["timestamp"], bool)
                    or not isinstance(block["timestamp"], int)
                    or block["timestamp"] < 0
                ):
                    return False

                if (
                    isinstance(block["nonce"], bool)
                    or not isinstance(block["nonce"], int)
                    or block["nonce"] < 0
                ):
                    return False

                if not isinstance(block["transactions"], list):
                    return False

                if not isinstance(block["allocations"], dict):
                    return False

                if self.calculate_hash(block) != block["hash"]:
                    return False

                if not block["hash"].startswith(
                    "0" * self.difficulty
                ):
                    return False

                if index == 0:
                    if block["previous_hash"] != "0":
                        return False

                    if block["transactions"]:
                        return False

                    for address, amount in block["allocations"].items():
                        if not valid_address(address):
                            return False

                        if (
                            isinstance(amount, bool)
                            or not isinstance(amount, int)
                            or amount <= 0
                        ):
                            return False

                        balances[address] = amount

                else:
                    if block["previous_hash"] != self.chain[index - 1]["hash"]:
                        return False

                    if block["allocations"]:
                        return False

                    for transaction in block["transactions"]:
                        if set(transaction.keys()) != {
                            "transaction_id", "sender", "recipient",
                            "amount", "timestamp", "signature"
                        }:
                            return False

                        tx_id = transaction["transaction_id"]
                        sender = transaction["sender"]
                        recipient = transaction["recipient"]
                        amount = transaction["amount"]
                        timestamp = transaction["timestamp"]
                        signature = transaction["signature"]

                        if not isinstance(tx_id, str) or not tx_id:
                            return False

                        if tx_id in transaction_ids:
                            return False

                        transaction_ids.add(tx_id)

                        if not valid_address(sender):
                            return False

                        if not valid_address(recipient):
                            return False

                        if sender == recipient:
                            return False

                        if (
                            isinstance(amount, bool)
                            or not isinstance(amount, int)
                            or amount <= 0
                        ):
                            return False

                        if (
                            isinstance(timestamp, bool)
                            or not isinstance(timestamp, int)
                            or timestamp < 0
                        ):
                            return False

                        unsigned = {
                            key: value
                            for key, value in transaction.items()
                            if key != "signature"
                        }

                        if not Wallet.verify_signature(
                            unsigned, signature
                        ):
                            return False

                        if balances.get(sender, 0) < amount:
                            return False

                        balances[sender] = balances.get(sender, 0) - amount
                        balances[recipient] = (
                            balances.get(recipient, 0) + amount
                        )

            except Exception:
                return False

        return True


if __name__ == "__main__":
    print(VERSION)
    print("----------------------------")

    alice = Wallet()
    bob = Wallet()

    globalcoin = Blockchain(
        difficulty=3,
        initial_balances={
            alice.get_address(): 100
        }
    )

    print("Alice Wallet:", alice.get_address())
    print("Bob Wallet:", bob.get_address())

    print("Alice Initial Balance:", globalcoin.get_balance(
        alice.get_address()
    ))

    transaction_id = globalcoin.add_transaction(
        alice,
        bob.get_address(),
        10
    )

    print("Transaction ID:", transaction_id)

    block = globalcoin.mine_pending_transactions()

    print("New Block:", block["index"])
    print("Total Blocks:", len(globalcoin.chain))

    print("Alice Balance:", globalcoin.get_balance(
        alice.get_address()
    ))

    print("Bob Balance:", globalcoin.get_balance(
        bob.get_address()
    ))

    print("Blockchain Valid:", globalcoin.is_chain_valid())

    print("----------------------------")
    print("GLOBALCOIN TEST COMPLETED")
