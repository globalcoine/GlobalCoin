
import unittest
import tempfile
import os

from blockchain import (
    Blockchain,
    Wallet,
    MAX_SUPPLY,
    BLOCK_REWARD,
    HALVING_INTERVAL
)


class GlobalCoinSecurityTests(unittest.TestCase):

    def setUp(self):
        self.alice = Wallet()
        self.bob = Wallet()
        self.miner = Wallet()

        self.blockchain = Blockchain(
            difficulty=2,
            initial_balances={
                self.alice.get_address(): 100
            },
            transaction_fee=1
        )

    def test_maximum_supply(self):
        self.assertEqual(MAX_SUPPLY, 21_000_000)
        self.assertLessEqual(
            self.blockchain.get_total_supply(),
            MAX_SUPPLY
        )

    def test_block_reward_and_halving(self):
        self.assertEqual(
            self.blockchain.get_block_reward(1),
            BLOCK_REWARD
        )

        self.assertEqual(
            self.blockchain.get_block_reward(HALVING_INTERVAL + 1),
            BLOCK_REWARD // 2
        )

    def test_invalid_allocation_rejected(self):
        with self.assertRaises(ValueError):
            Blockchain(
                initial_balances={
                    self.alice.get_address(): MAX_SUPPLY + 1
                }
            )

    def test_forged_signature_rejected(self):
        transaction = {
            "transaction_id": "fake-transaction",
            "sender": self.bob.get_address(),
            "recipient": self.alice.get_address(),
            "amount": 10,
            "fee": 1,
            "timestamp": 1000
        }

        signature = self.alice.sign_transaction(transaction)

        self.assertFalse(
            Wallet.verify_signature(transaction, signature)
        )

    def test_overspending_rejected(self):
        with self.assertRaises(ValueError):
            self.blockchain.add_transaction(
                self.alice,
                self.bob.get_address(),
                100,
                fee=1
            )

    def test_negative_amount_rejected(self):
        with self.assertRaises(ValueError):
            self.blockchain.add_transaction(
                self.alice,
                self.bob.get_address(),
                -10
            )

    def test_negative_fee_rejected(self):
        with self.assertRaises(ValueError):
            self.blockchain.add_transaction(
                self.alice,
                self.bob.get_address(),
                10,
                fee=-1
            )

    def test_transaction_fee(self):
        self.blockchain.add_transaction(
            self.alice,
            self.bob.get_address(),
            10
        )

        block = self.blockchain.mine_pending_transactions(
            self.miner.get_address()
        )

        self.assertEqual(block["transactions"][0]["fee"], 1)
        self.assertEqual(
            self.blockchain.get_balance(self.alice.get_address()),
            89
        )
        self.assertEqual(
            self.blockchain.get_balance(self.bob.get_address()),
            10
        )
        self.assertEqual(
            self.blockchain.get_balance(self.miner.get_address()),
            BLOCK_REWARD + 1
        )

    def test_duplicate_transaction_rejected(self):
        self.blockchain.add_transaction(
            self.alice,
            self.bob.get_address(),
            10
        )

        duplicate = self.blockchain.pending_transactions[0].copy()
        self.blockchain.pending_transactions.append(duplicate)

        self.blockchain.mine_pending_transactions()

        self.assertFalse(self.blockchain.is_chain_valid())

    def test_block_tampering_detected(self):
        self.blockchain.add_transaction(
            self.alice,
            self.bob.get_address(),
            10
        )

        self.blockchain.mine_pending_transactions()

        self.blockchain.chain[1]["transactions"][0]["amount"] = 20

        self.assertFalse(self.blockchain.is_chain_valid())

    def test_wallet_save_and_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, "wallet.json")
            password = "GlobalCoin-Test-2026"

            self.alice.save(filename, password)

            restored = Wallet.load(filename, password)

            self.assertEqual(
                self.alice.get_address(),
                restored.get_address()
            )

            with open(filename, encoding="utf-8") as file:
                contents = file.read()

            self.assertNotIn(
                self.alice.get_private_key(),
                contents
            )

    def test_wrong_wallet_password_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, "wallet.json")

            self.alice.save(filename, "GlobalCoin-Test-2026")

            with self.assertRaises(Exception):
                Wallet.load(filename, "Wrong-Password-2026")

    def test_normal_transaction(self):
        self.blockchain.add_transaction(
            self.alice,
            self.bob.get_address(),
            10
        )

        self.blockchain.mine_pending_transactions()

        self.assertEqual(
            self.blockchain.get_balance(self.alice.get_address()),
            89
        )

        self.assertEqual(
            self.blockchain.get_balance(self.bob.get_address()),
            10
        )

        self.assertTrue(self.blockchain.is_chain_valid())

    def test_mining_without_transactions(self):
        block = self.blockchain.mine_pending_transactions(
            self.miner.get_address()
        )

        self.assertIsNone(block)


if __name__ == "__main__":
    unittest.main(verbosity=2)
