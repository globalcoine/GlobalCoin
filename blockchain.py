
import hashlib
import json
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization


class Wallet:
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def get_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

    def get_address(self):
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return public_bytes.hex()

    def sign_transaction(self, transaction):
        message = json.dumps(
            transaction,
            sort_keys=True,
            separators=(",", ":")
        ).encode()

        return self.private_key.sign(message).hex()

    @staticmethod
    def verify_signature(transaction, signature):
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(transaction["sender"])
            )

            message = json.dumps(
                transaction,
                sort_keys=True,
                separators=(",", ":")
            ).encode()

            public_key.verify(bytes.fromhex(signature), message)
            return True

        except Exception:
            return False


class Blockchain:
    def __init__(self, difficulty=3):
        self.difficulty = difficulty
        self.chain = []
        self.pending_transactions = []
        self.create_genesis_block()

    def calculate_hash(self, block):
        data = {
            "index": block["index"],
            "timestamp": block["timestamp"],
            "transactions": block["transactions"],
            "previous_hash": block["previous_hash"],
            "nonce": block["nonce"]
        }

        encoded = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()

        return hashlib.sha256(encoded).hexdigest()

    def mine_block(self, block):
        target = "0" * self.difficulty

        while True:
            block_hash = self.calculate_hash(block)

            if block_hash.startswith(target):
                block["hash"] = block_hash
                return block

            block["nonce"] += 1

    def create_genesis_block(self):
        genesis = {
            "index": 0,
            "timestamp": int(time.time()),
            "transactions": [],
            "previous_hash": "0",
            "nonce": 0
        }

        self.chain.append(self.mine_block(genesis))

    def add_transaction(self, wallet, recipient, amount):
        if not isinstance(wallet, Wallet):
            raise ValueError("Invalid wallet")

        if not isinstance(recipient, str) or not recipient.strip():
            raise ValueError("Invalid recipient")

        if (
            isinstance(amount, bool)
            or not isinstance(amount, int)
            or amount <= 0
        ):
            raise ValueError("Amount must be a positive integer")

        transaction = {
            "transaction_id": str(uuid.uuid4()),
            "sender": wallet.get_address(),
            "recipient": recipient.strip(),
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
            "nonce": 0
        }

        mined_block = self.mine_block(block)
        self.chain.append(mined_block)
        self.pending_transactions = []

        return mined_block

    def is_chain_valid(self):
        for index, block in enumerate(self.chain):
            if self.calculate_hash(block) != block["hash"]:
                return False

            if not block["hash"].startswith("0" * self.difficulty):
                return False

            if index == 0:
                if block["previous_hash"] != "0":
                    return False
            else:
                if block["previous_hash"] != self.chain[index - 1]["hash"]:
                    return False

            for transaction in block["transactions"]:
                signature = transaction.get("signature")

                if not signature:
                    return False

                unsigned_transaction = {
                    key: value
                    for key, value in transaction.items()
                    if key != "signature"
                }

                if not Wallet.verify_signature(
                    unsigned_transaction,
                    signature
                ):
                    return False

        return True


if __name__ == "__main__":
    globalcoin = Blockchain()

    alice = Wallet()
    bob = Wallet()

    transaction_id = globalcoin.add_transaction(
        alice,
        bob.get_address(),
        10
    )

    new_block = globalcoin.mine_pending_transactions()

    print("GLOBALCOIN VERSION 3")
    print("--------------------")
    print("Alice Wallet:", alice.get_address())
    print("Bob Wallet:", bob.get_address())
    print("Transaction ID:", transaction_id)
    print("Total Blocks:", len(globalcoin.chain))
    print("Blockchain Valid:", globalcoin.is_chain_valid())
