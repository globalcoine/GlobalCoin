
import unittest
import tempfile
import os

from blockchain import Blockchain, Wallet


class GlobalCoinSecurityTests(unittest.TestCase):

    def setUp(self):
        self.alice = Wallet()
        self.bob = Wallet()

        self.blockchain = Blockchain(
            difficulty=2,
            initial_balances={
                self.alice.get_address(): 100
            }
        )

    def test_forged_signature_rejected(self):
        fake_transaction = {
            "transaction_id": "fake-transaction",
            "sender": self.bob.get_address(),
            "recipient": self.alice.get_address(),
            "amount": 10,
            "timestamp": 1000
        }

        # Alice tries to sign a transaction claiming Bob is the sender.
        fake_signature = self.alice.sign_transaction(
            fake_transaction
        )

        self.assertFalse(
            Wallet.verify_signature(
                fake_transaction,
                fake_signature
            )
        )

    def test_overspending_rejected(self):
        with self.assertRaises(ValueError):
            self.blockchain.add_transaction(
                self.alice,
                self.bob.get_address(),
                101
            )

    def test_negative_amount_rejected(self):
        with self.assertRaises(ValueError):
            self.blockchain.add_transaction(
                self.alice,
                self.bob.get_address(),
                -10
            )

    def test_duplicate_transaction_rejected(self):
        self.blockchain.add_transaction(
            self.alice,
            self.bob.get_address(),
            10
        )

        # Simulate a duplicated transaction in a block.
        duplicate = self.blockchain.pending_transactions[0].copy()

        self.blockchain.pending_transactions.append(duplicate)
        self.blockchain.mine_pending_transactions()

        self.assertFalse(
            self.blockchain.is_chain_valid()
        )

    def test_block_tampering_detected(self):
        self.blockchain.add_transaction(
            self.alice,
            self.bob.get_address(),
            10
        )

        self.blockchain.mine_pending_transactions()

        # Modify a transaction after mining.
        self.blockchain.chain[1]["transactions"][0]["amount"] = 20

        self.assertFalse(
            self.blockchain.is_chain_valid()
        )

    def test_wallet_save_and_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, "wallet.json")
            password = "GlobalCoin-Test-2026"

            self.alice.save(filename, password)

            restored_wallet = Wallet.load(
                filename,
                password
            )

            self.assertEqual(
                self.alice.get_address(),
                restored_wallet.get_address()
            )

            self.assertNotIn(
                self.alice.get_private_key(),
                open(filename, encoding="utf-8").read()
            )

    def test_wrong_wallet_password_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, "wallet.json")

            self.alice.save(
                filename,
                "GlobalCoin-Test-2026"
            )

            with self.assertRaises(Exception):
                Wallet.load(
                    filename,
                    "Wrong-Password-2026"
                )

    def test_normal_transaction(self):
        self.blockchain.add_transaction(
            self.alice,
            self.bob.get_address(),
            10
        )

        self.blockchain.mine_pending_transactions()

        self.assertEqual(
            self.blockchain.get_balance(
                self.alice.get_address()
            ),
            90
        )

        self.assertEqual(
            self.blockchain.get_balance(
                self.bob.get_address()
            ),
            10
        )

        self.assertTrue(
            self.blockchain.is_chain_valid()
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
