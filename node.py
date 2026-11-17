
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from blockchain import Blockchain, Wallet
from storage import save_blockchain, load_blockchain


CHAIN_FILE = "globalcoin_chain.json"
HOST = "127.0.0.1"
PORT = 8000


def get_blockchain():
    try:
        return load_blockchain(CHAIN_FILE)
    except FileNotFoundError:
        blockchain = Blockchain()
        save_blockchain(blockchain, CHAIN_FILE)
        return blockchain


blockchain = get_blockchain()


class GlobalCoinHandler(BaseHTTPRequestHandler):

    def send_json(self, status, data):
        body = json.dumps(data, indent=4).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/status":
            self.send_json(200, {
                "name": "GLOBALCOIN",
                "version": "5",
                "blocks": len(blockchain.chain),
                "difficulty": blockchain.difficulty,
                "total_supply": blockchain.get_total_supply(),
                "maximum_supply": 21_000_000,
                "valid": blockchain.is_chain_valid()
            })

        elif parsed.path == "/chain":
            self.send_json(200, {
                "chain": blockchain.chain
            })

        elif parsed.path == "/balance":
            params = parse_qs(parsed.query)
            address = params.get("address", [None])[0]

            try:
                balance = blockchain.get_balance(address)
                self.send_json(200, {
                    "address": address,
                    "balance": balance
                })
            except ValueError:
                self.send_json(400, {
                    "error": "Invalid wallet address"
                })

        else:
            self.send_json(404, {
                "error": "Endpoint not found"
            })

    def do_POST(self):
        global blockchain

        if self.path == "/mine":
            try:
                data = self.read_json()
                miner_address = data.get("miner_address")

                block = blockchain.mine_pending_transactions(
                    miner_address
                )

                save_blockchain(blockchain, CHAIN_FILE)

                self.send_json(200, {
                    "message": "Block mined successfully",
                    "block": block
                })

            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self.send_json(400, {
                    "error": str(error)
                })

            except Exception:
                self.send_json(500, {
                    "error": "Mining failed"
                })

        else:
            self.send_json(404, {
                "error": "Endpoint not found"
            })

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))

        if length <= 0 or length > 10000:
            raise ValueError("Invalid request size")

        data = json.loads(self.rfile.read(length))

        if not isinstance(data, dict):
            raise ValueError("JSON object required")

        return data

    def log_message(self, format, *args):
        print("GLOBALCOIN:", format % args)


if __name__ == "__main__":
    print("GLOBALCOIN NODE STARTED")
    print("Address: http://127.0.0.1:8000")

    server = ThreadingHTTPServer(
        (HOST, PORT),
        GlobalCoinHandler
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("GLOBALCOIN NODE STOPPED")
    finally:
        server.server_close()
