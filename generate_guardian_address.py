#!/usr/bin/env python3
import os
from bitcoin import SelectParams
SelectParams("testnet")
from bitcoin.wallet import CBitcoinSecret, P2WPKHBitcoinAddress
from bitcoin.core.key import CPubKey
from bitcoin.core import Hash160

# Generate random 32-byte private key
secret = CBitcoinSecret.from_secret_bytes(os.urandom(32))

# Get compressed public key
pubkey = CPubKey(secret.pub)

# Compute HASH160 of the pubkey
pubkey_hash = Hash160(pubkey)

# Create a valid P2WPKH address manually
address = P2WPKHBitcoinAddress.from_bytes(0, pubkey_hash)

print("WIF (private key):", secret)
print("Testnet P2WPKH address:", address)

