import re
from hashlib import sha3_256

def keccak256(data: str) -> str:
    """Hash the input data using keccak256."""
    return sha3_256(data.encode('utf-8')).hexdigest()

def to_checksum_address(address: str, internal: bool = False) -> str:
    if address is None:
        return ""

    if not internal:
        if not re.match(r"^(0x)?[0-9a-f]{40}$", address, re.IGNORECASE):
            raise ValueError("Invalid Ethereum address")
        address = address.lower()[2:]

    address_hash = keccak256(address)
    checksum_address = "0x"

    for i, char in enumerate(address):
        if int(address_hash[i], 16) > 7:
            checksum_address += char.upper()
        else:
            checksum_address += char

    return checksum_address

def check_checksum_address(address: str) -> bool:
    if len(address) != 42 or not address.lower().startswith("0x"):
        return False

    address = address[2:]
    address_hash = keccak256(address.lower())

    for i in range(40):
        if int(address_hash[i], 16) > 7:
            if address[i].islower():
                return False
        elif address[i].isupper():
            return False

    return True

def is_valid_address(address: str, lenient: bool = False) -> bool:
    if not isinstance(address, str):
        return False

    if lenient:
        return (
            bool(re.match(r"^(0x|0X)?[0-9a-f]{40}$", address)) or
            bool(re.match(r"^(0x|0X)?[0-9A-F]{40}$", address)) or
            check_checksum_address(address)
        )

    return check_checksum_address(address)
