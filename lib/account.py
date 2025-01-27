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


secp256k1 = None


def initialize_ethereum_account_verifiable(s):
    global secp256k1
    secp256k1 = s


__all__ = ["EthereumAccount", "initialize_ethereum_account_verifiable"]
