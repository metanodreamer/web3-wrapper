import re
import hashlib

def keccak256(data: str) -> str:
    return hashlib.new("sha3_256", bytes.fromhex(data)).hexdigest()

def to_checksum_address(address: str, internal: bool = False) -> str:
    if address is None:
        return ""
    
    if not internal:
        if not re.match(r'^(0x)?[0-9a-fA-F]{40}$', address):
            raise ValueError("Invalid Ethereum address")
        address = address.lower().replace("0x", "")
    
    address_hash = keccak256(address)
    checksum_address = "0x"
    
    for i, char in enumerate(address):
        checksum_address += char.upper() if int(address_hash[i], 16) > 7 else char
    
    return checksum_address

def check_checksum_address(address: str) -> bool:
    if len(address) != 42 or not address.lower().startswith("0x"):
        return False
    
    address_body = address[2:]
    address_hash = keccak256(address_body.lower())
    
    for i in range(40):
        if int(address_hash[i], 16) > 7:
            if "a" <= address_body[i] <= "z":
                return False
        elif "A" <= address_body[i] <= "Z":
            return False
    
    return True

def is_valid_address(address: str, lenient: bool = False) -> bool:
    if not isinstance(address, str):
        return False
    
    if lenient:
        return (
            bool(re.match(r'^(0x|0X)?[0-9a-f]{40}$', address)) or
            bool(re.match(r'^(0x|0X)?[0-9A-F]{40}$', address)) or
            check_checksum_address(address)
        )
    
    return check_checksum_address(address)
