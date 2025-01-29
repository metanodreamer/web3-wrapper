import hashlib
from eth_utils import is_checksum_address, to_checksum_address

GAS_LIMIT = 12500000


class EthereumAccount:
    def __init__(self, connection, address):
        if isinstance(address, (bytes, bytearray)) and len(address) == 32:
            raise TypeError("Private keys must be 32 bytes in length.")

        if not is_checksum_address(address):
            raise TypeError("Argument #2 isn't an Ethereum address.")

        self._connection = connection
        self.address = to_checksum_address(address)
        self.nonce = 0

    async def update_nonce(self):
        nonce = await self._connection.get_transaction_count(self.address)
        if nonce > self.nonce:
            self.nonce = nonce
        return self.nonce

    def sign(self):
        raise ValueError(f"Private key for account {self.address} is unknown.")

    async def sign_data(self, data):
        binary_data = data if isinstance(data, bytes) else data.encode()
        full_sig = await self._connection.sign(self.address, binary_data)
        prefix = f"\x19Ethereum Signed Message:\n{len(binary_data)}".encode()
        hash_value = hashlib.sha3_256(prefix + binary_data).digest()
        return {
            "messageHash": hash_value,
            "v": full_sig[64],
            "r": full_sig[:32],
            "s": full_sig[32:64],
            "signature": "0x" + full_sig.hex(),
        }

    def verify_signature(self, data, sig):
        if not secp256k1:
            raise RuntimeError("secp256k1 library is not initialized.")

        binary_data = data if isinstance(data, bytes) else data.encode()
        hash_value = hashlib.sha3_256(binary_data).digest()

        if isinstance(sig, str):
            full_sig = bytes.fromhex(sig[2:130])
            recovery_id = int(sig[130:], 16) - 27
        else:
            full_sig = sig["r"] + sig["s"]
            recovery_id = sig["v"] - 27

        recovered_pub_key = secp256k1.recover(full_sig, recovery_id, hash_value)
        return (
            hashlib.sha3_256(recovered_pub_key).hexdigest()[:40]
            == self.address[2:].lower()
        )

    async def transfer(self, account, amount, gas_price, gas_amount, nonce):
        # Validate inputs
        if amount < 0:
            raise ValueError("Transfer amount must be positive")
        if gas_price < 0:
            raise ValueError("Gas price must be positive")
        if gas_amount < 21000:  # Minimum gas required for ETH transfer
            raise ValueError("Gas amount must be at least 21000")

        to_address = (
            account.address
            if isinstance(account, EthereumAccount)
            else account if isinstance(account, str) else None
        )
        if not to_address:
            raise TypeError("Invalid account or contract")
        if not is_checksum_address(to_address):
            raise ValueError("Invalid Ethereum address format")

        return await self.send_transaction(
            {
                "to": to_address,
                "gasPrice": gas_price,
                "gas": gas_amount,
                "value": amount,
                "nonce": nonce,
            }
        )

    async def is_contract(self, address):
        """Check if an address is a contract address"""
        code = await self._connection.get_code(address)
        return code != "0x" and code != "0x0"

    async def get_transaction_receipt(self, tx_hash):
        """Get the transaction receipt for a given transaction hash"""
        receipt = await self._connection.get_transaction_receipt(tx_hash)
        if receipt is None:
            raise ValueError(f"Transaction {tx_hash.hex()} not found")
        return receipt

    async def send_transaction(self, tx_data):
        if "nonce" not in tx_data:
            await self.update_nonce()
            tx_data["nonce"] = self.nonce

        # Validate transaction data
        if "value" in tx_data and tx_data["value"] < 0:
            raise ValueError("Transaction value must be positive")

        if "gasPrice" not in tx_data:
            tx_data["gasPrice"] = await self._connection.get_gas_price()

        if "to" in tx_data and isinstance(tx_data["to"], EthereumAccount):
            tx_data["to"] = tx_data["to"].address

        if "gas" not in tx_data:
            tx_data["gas"] = await self._connection.estimate_gas(
                {
                    "from": self.address,
                    "to": tx_data["to"],
                    "data": tx_data.get("data", b""),
                    "value": tx_data.get("value", 0),
                }
            )

            if tx_data["gas"] > 21000:
                tx_data["gas"] = min(int(tx_data["gas"] * 1.25), GAS_LIMIT)

        tx_data["from"] = self.address
        tx_hash = await self._connection.send_transaction(tx_data)
        self.nonce += 1
        return tx_hash

    async def balance(self, block_number=None):
        return await self._connection.get_balance(self.address, block_number)

    def __str__(self):
        return self.address

    def set_sender_for(self, contract):
        contract.signer = self

    async def get_token_balance(self, token_address):
        """Get ERC20 token balance for this account"""
        if not await self.is_contract(token_address):
            raise ValueError("Provided address is not a contract")

        # ERC20 balanceOf function signature
        data = bytes.fromhex("70a08231" + "0" * 24 + self.address[2:])

        result = await self._connection.call({"to": token_address, "data": data})
        return int(result, 16)

    async def transfer_token(self, token_address, to_address, amount, gas_price=None):
        """Transfer ERC20 tokens to another address"""
        if not is_checksum_address(to_address):
            raise ValueError("Invalid recipient address")
        if amount <= 0:
            raise ValueError("Amount must be positive")

        # ERC20 transfer function signature
        data = (
            bytes.fromhex("a9059cbb")  # transfer method ID
            + bytes.fromhex("0" * 24 + to_address[2:])  # padding + address
            + amount.to_bytes(32, "big")  # amount in bytes
        )

        tx_data = {"to": token_address, "data": data, "value": 0}

        if gas_price:
            tx_data["gasPrice"] = gas_price

        return await self.send_transaction(tx_data)

    async def get_transaction_history(self, start_block=0, end_block="latest"):
        """Get all transactions involving this account"""
        # Get sent transactions
        sent_filter = {
            "fromBlock": start_block,
            "toBlock": end_block,
            "address": self.address,
        }

        # Get received transactions
        received_filter = {
            "fromBlock": start_block,
            "toBlock": end_block,
            "to": self.address,
        }

        sent = await self._connection.get_logs(sent_filter)
        received = await self._connection.get_logs(received_filter)

        return {"sent": sent, "received": received}

    async def approve_token_spending(self, token_address, spender_address, amount):
        """Approve an address to spend tokens on behalf of this account"""
        if not is_checksum_address(spender_address):
            raise ValueError("Invalid spender address")
        if amount < 0:
            raise ValueError("Amount must be non-negative")

        # ERC20 approve function signature
        data = (
            bytes.fromhex("095ea7b3")  # approve method ID
            + bytes.fromhex("0" * 24 + spender_address[2:])  # padding + address
            + amount.to_bytes(32, "big")  # amount in bytes
        )

        return await self.send_transaction(
            {"to": token_address, "data": data, "value": 0}
        )


secp256k1 = None


def initialize_ethereum_account_verifiable(s):
    global secp256k1
    secp256k1 = s


__all__ = ["EthereumAccount", "initialize_ethereum_account_verifiable"]
