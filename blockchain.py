import hashlib
import json
import time
import math


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

    def add_transaction(self, sender, recipient, amount):

        if not isinstance(sender, str) or not sender.strip():
            raise ValueError("Invalid sender address")

        if not isinstance(recipient, str) or not recipient.strip():
            raise ValueError("Invalid recipient address")

        if (
            isinstance(amount, bool)
            or not isinstance(amount, (int, float))
            or not math.isfinite(amount)
            or amount <= 0
        ):
            raise ValueError("Invalid transaction amount")

        transaction = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount
        }

        self.pending_transactions.append(transaction)

        return True

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

            if not block["hash"].startswith(
                "0" * self.difficulty
            ):
                return False

            if index == 0:

                if block["previous_hash"] != "0":
                    return False

            else:

                previous_block = self.chain[index - 1]

                if block["previous_hash"] != previous_block["hash"]:
                    return False

        return True


if __name__ == "__main__":

    globalcoin = Blockchain()

    globalcoin.add_transaction(
        "Alice",
        "Bob",
        10
    )

    new_block = globalcoin.mine_pending_transactions()

    print("GLOBALCOIN BLOCKCHAIN")
    print("---------------------")

    print("New Block:", new_block)
    print("Total Blocks:", len(globalcoin.chain))
    print("Blockchain Valid:", globalcoin.is_chain_valid())
