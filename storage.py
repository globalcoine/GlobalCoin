
import json
import os
import tempfile

from blockchain import Blockchain, VERSION


def save_blockchain(blockchain, filename="globalcoin_chain.json"):
    if not blockchain.is_chain_valid():
        raise ValueError("Cannot save an invalid blockchain")

    data = {
        "version": VERSION,
        "difficulty": blockchain.difficulty,
        "transaction_fee": blockchain.transaction_fee,
        "chain": blockchain.chain
    }

    directory = os.path.dirname(os.path.abspath(filename))

    fd, temporary_file = tempfile.mkstemp(
        dir=directory,
        prefix="globalcoin_",
        suffix=".tmp"
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

        os.replace(temporary_file, filename)

    except Exception:
        if os.path.exists(temporary_file):
            os.remove(temporary_file)
        raise


def load_blockchain(filename="globalcoin_chain.json"):
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)

    if data.get("version") != VERSION:
        raise ValueError("Unsupported blockchain version")

    chain = data.get("chain")

    if not isinstance(chain, list) or not chain:
        raise ValueError("Invalid blockchain data")

    difficulty = data.get("difficulty")
    transaction_fee = data.get("transaction_fee")

    blockchain = Blockchain(
        difficulty=difficulty,
        initial_balances=chain[0].get("allocations"),
        transaction_fee=transaction_fee
    )

    blockchain.chain = chain

    if not blockchain.is_chain_valid():
        raise ValueError("Blockchain integrity check failed")

    return blockchain
