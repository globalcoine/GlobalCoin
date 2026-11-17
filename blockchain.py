
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


VERSION = "GLOBALCOIN VERSION 5"

MAX_SUPPLY = 21_000_000
BLOCK_REWARD = 50
HALVING_INTERVAL = 210_000
DEFAULT_TRANSACTION_FEE = 1


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
    def __init__(
        self,
        difficulty=3,
        initial_balances=None,
        transaction_fee=DEFAULT_TRANSACTION_FEE
    ):
        if (
            isinstance(difficulty, bool)
            or not isinstance(difficulty, int)
            or not 1 <= difficulty <= 6
        ):
            raise ValueError("Difficulty must be between 1 and 6")

        if (
            isinstance(transaction_fee, bool)
            or not isinstance(transaction_fee, int)
            or transaction_fee < 0
        ):
            raise ValueError("Transaction fee must be non-negative")

        self.difficulty = difficulty
        self.transaction_fee = transaction_fee
        self.chain = []
        self.pending_transactions = []

        allocations = initial_balances or {}

        if not isinstance(allocations, dict):
            raise ValueError("Initial balances must be a dictionary")

        for address, amount in allocations.items():
            if not valid_address(address):
                raise ValueError("Invalid allocation address")

            if (
                isinstance(amount, bool)
                or not isinstance(amount, int)
                or amount <= 0
            ):
                raise ValueError("Invalid initial balance")

        if sum(allocations.values()) > MAX_SUPPLY:
            raise ValueError("Initial supply exceeds maximum supply")

        self.create_genesis_block(allocations)

    def calculate_hash(self, block):
        data = {
            "index": block["index"],
            "timestamp": block["timestamp"],
            "transactions": block["transactions"],
            "previous_hash": block["previous_hash"],
            "nonce": block["nonce"],
            "allocations": block["allocations"],
            "miner": block["miner"],
            "reward": block["reward"]
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
            "allocations": allocations.copy(),
            "miner": None,
            "reward": 0
        }

        self.chain.append(self.mine_block(genesis))

    def get_block_reward(self, height):
        if (
            isinstance(height, bool)
            or not isinstance(height, int)
            or height < 1
        ):
            raise ValueError("Invalid block height")

        halvings = (height - 1) // HALVING_INTERVAL
        return BLOCK_REWARD // (2 ** halvings)

    def get_balances(self, include_pending=False):
        balances = {}

        for address, amount in self.chain[0]["allocations"].items():
            balances[address] = amount

        for block in self.chain[1:]:
            for transaction in block["transactions"]:
                sender = transaction["sender"]
                recipient = transaction["recipient"]
                amount = transaction["amount"]
                fee = transaction["fee"]

                balances[sender] = (
                    balances.get(sender, 0) - amount - fee
                )
                balances[recipient] = (
                    balances.get(recipient, 0) + amount
                )

            miner = block["miner"]

            if miner is not None:
                fees = sum(
                    tx["fee"] for tx in block["transactions"]
                )
                balances[miner] = (
                    balances.get(miner, 0)
                    + block["reward"]
                    + fees
                )

        if include_pending:
            for transaction in self.pending_transactions:
                sender = transaction["sender"]
                recipient = transaction["recipient"]

                balances[sender] = (
                    balances.get(sender, 0)
                    - transaction["amount"]
                    - transaction["fee"]
                )

                balances[recipient] = (
                    balances.get(recipient, 0)
                    + transaction["amount"]
                )

        return balances

    def get_total_supply(self):
        return sum(self.get_balances().values())

    def get_balance(self, address, include_pending=False):
        if not valid_address(address):
            raise ValueError("Invalid wallet address")

        return self.get_balances(
            include_pending
        ).get(address, 0)

    def add_transaction(self, wallet, recipient, amount, fee=None):
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

        if fee is None:
            fee = self.transaction_fee

        if (
            isinstance(fee, bool)
            or not isinstance(fee, int)
            or fee < 0
        ):
            raise ValueError("Invalid transaction fee")

        sender = wallet.get_address()

        if sender == recipient:
            raise ValueError("Cannot send to the same wallet")

        if self.get_balance(sender, True) < amount + fee:
            raise ValueError("Insufficient balance")

        transaction = {
            "transaction_id": str(uuid.uuid4()),
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "fee": fee,
            "timestamp": int(time.time())
        }

        signature = wallet.sign_transaction(transaction)

        if not Wallet.verify_signature(transaction, signature):
            raise ValueError("Signature verification failed")

        transaction["signature"] = signature
        self.pending_transactions.append(transaction)

        return transaction["transaction_id"]

    def mine_pending_transactions(self, miner_address=None):
        if (
            miner_address is not None
            and not valid_address(miner_address)
        ):
            raise ValueError("Invalid miner address")

        height = len(self.chain)
        current_supply = self.get_total_supply()

        if miner_address is None:
            reward = 0
        else:
            remaining_supply = MAX_SUPPLY - current_supply
            reward = min(
                self.get_block_reward(height),
                remaining_supply
            )

        block = {
            "index": height,
            "timestamp": int(time.time()),
            "transactions": self.pending_transactions.copy(),
            "previous_hash": self.chain[-1]["hash"],
            "nonce": 0,
            "allocations": {},
            "miner": miner_address,
            "reward": reward
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
                    "index",
                    "timestamp",
                    "transactions",
                    "previous_hash",
                    "nonce",
                    "allocations",
                    "miner",
                    "reward",
                    "hash"
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

                if (
                    isinstance(block["reward"], bool)
                    or not isinstance(block["reward"], int)
                    or block["reward"] < 0
                ):
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

                    if block["miner"] is not None:
                        return False

                    if block["reward"] != 0:
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

                    if sum(balances.values()) > MAX_SUPPLY:
                        return False

                else:
                    if (
                        block["previous_hash"]
                        != self.chain[index - 1]["hash"]
                    ):
                        return False

                    if block["allocations"]:
                        return False

                    miner = block["miner"]

                    if miner is not None and not valid_address(miner):
                        return False

                    current_supply = sum(balances.values())

                    if miner is None:
                        expected_reward = 0
                    else:
                        expected_reward = min(
                            self.get_block_reward(index),
                            MAX_SUPPLY - current_supply
                        )

                    if block["reward"] != expected_reward:
                        return False

                    block_fees = 0

                    for transaction in block["transactions"]:
                        if set(transaction.keys()) != {
                            "transaction_id",
                            "sender",
                            "recipient",
                            "amount",
                            "fee",
                            "timestamp",
                            "signature"
                        }:
                            return False

                        tx_id = transaction["transaction_id"]
                        sender = transaction["sender"]
                        recipient = transaction["recipient"]
                        amount = transaction["amount"]
                        fee = transaction["fee"]
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
                            isinstance(fee, bool)
                            or not isinstance(fee, int)
                            or fee < 0
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

                        if balances.get(sender, 0) < amount + fee:
                            return False

                        balances[sender] = (
                            balances.get(sender, 0) - amount - fee
                        )

                        balances[recipient] = (
                            balances.get(recipient, 0) + amount
                        )

                        block_fees += fee

                    if miner is not None:
                        balances[miner] = (
                            balances.get(miner, 0)
                            + block["reward"]
                            + block_fees
                        )

                    if sum(balances.values()) > MAX_SUPPLY:
                        return False

            except Exception:
                return False

        return True


if __name__ == "__main__":
    print(VERSION)
    print("----------------------------")

    alice = Wallet()
    bob = Wallet()
    miner = Wallet()

    globalcoin = Blockchain(
        difficulty=3,
        initial_balances={
            alice.get_address(): 100
        }
    )

    print("Maximum Supply:", MAX_SUPPLY, "GCOIN")
    print("Block Reward:", globalcoin.get_block_reward(1), "GCOIN")

    print(
        "Alice Initial Balance:",
        globalcoin.get_balance(alice.get_address())
    )

    transaction_id = globalcoin.add_transaction(
        alice,
        bob.get_address(),
        10
    )

    print("Transaction ID:", transaction_id)

    block = globalcoin.mine_pending_transactions(
        miner.get_address()
    )

    print("New Block:", block["index"])
    print("Block Reward:", block["reward"])
    print("Total Blocks:", len(globalcoin.chain))

    print("Alice Balance:", globalcoin.get_balance(alice.get_address()))
    print("Bob Balance:", globalcoin.get_balance(bob.get_address()))
    print("Miner Balance:", globalcoin.get_balance(miner.get_address()))
    print("Total Supply:", globalcoin.get_total_supply())
    print("Blockchain Valid:", globalcoin.is_chain_valid())

    empty_block = globalcoin.mine_pending_transactions(
        miner.get_address()
    )

    print("Empty Block Mining:", empty_block["index"])
    print("Empty Block Reward:", empty_block["reward"])
    print("Blockchain Valid After Empty Mining:", globalcoin.is_chain_valid())

    print("----------------------------")
    print("GLOBALCOIN VERSION 5 COMPLETED")
