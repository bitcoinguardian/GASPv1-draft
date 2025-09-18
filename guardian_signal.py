#!/usr/bin/env python3
"""
guardian_signal.py - Guardian Lock/Unlock transaction builder with UTXO address
"""

import argparse
import requests
import hashlib
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey, P2wpkhAddress
from bitcoinutils.utils import encode_varint
import struct
import ecdsa
import ecdsa.der
import ecdsa.util

MAX_SIGNAL_LEN = 40
DUST_LIMIT = 546
SIGHASH_ALL = 0x01

def create_guardian_signal(lock: bool, nonce: int) -> str:
    """Create a Guardian signal payload"""
    payload = f"guardv1.Lock={'true' if lock else 'false'}#{nonce}"
    if len(payload.encode("ascii")) > MAX_SIGNAL_LEN:
        raise ValueError(f"Payload exceeds {MAX_SIGNAL_LEN} bytes")
    if nonce < 0 or nonce > 2**32 - 1:
        raise ValueError(f"Nonce must be between 0 and {2**32 - 1}")
    if nonce != 0 and str(nonce).startswith("0"):
        raise ValueError("Nonce must not have leading zeros unless it is 0")
    return payload

def double_sha256(data: bytes) -> bytes:
    """Double SHA256 hash"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash256(data: bytes) -> bytes:
    """Hash256 (double SHA256) for Bitcoin"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def create_output(amount: int, script: bytes) -> bytes:
    """Create a transaction output"""
    return amount.to_bytes(8, 'little') + encode_varint(len(script)) + script

def compute_bip143_sighash(tx_version: int, hash_prevouts: bytes, hash_sequence: bytes,
                           outpoint: bytes, script_code: bytes, value: int, sequence: int,
                           hash_outputs: bytes, locktime: int, sighash_type: int) -> bytes:
    """Compute BIP-143 signature hash"""
    preimage = struct.pack('<i', tx_version)
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += outpoint
    preimage += script_code
    preimage += struct.pack('<q', value)
    preimage += struct.pack('<I', sequence)
    preimage += hash_outputs
    preimage += struct.pack('<I', locktime)
    preimage += struct.pack('<I', sighash_type)
    return hash256(preimage)

def sign_transaction_p2wpkh(private_key: PrivateKey, utxo_txid: str, utxo_vout: int,
                            utxo_amount: int, utxo_addr: str, outputs: list, sequence: int = 0xffffffff) -> tuple:
    """Sign a P2WPKH transaction using BIP-143 with canonical signatures"""
    pub_key = private_key.get_public_key()
    pub_key_bytes = bytes.fromhex(pub_key.to_hex())

    # Use UTXO address for scriptCode
    utxo_addr_obj = P2wpkhAddress(utxo_addr)
    script_pubkey = utxo_addr_obj.to_script_pub_key().to_bytes()
    pubkey_hash = script_pubkey[2:22]
    print(f"Debug: UTXO Pubkey hash: {pubkey_hash.hex()}")

    # Verify private key matches UTXO address
    # priv_addr = pub_key.get_address().to_string()
    # if priv_addr != utxo_addr:
    #    print(f"Warning: Private key address ({priv_addr}) does not match UTXO address ({utxo_addr})")

    prevout = bytes.fromhex(utxo_txid)[::-1] + struct.pack('<I', utxo_vout)
    hash_prevouts = hash256(prevout)
    print(f"Debug: hashPrevouts: {hash_prevouts.hex()}")
    hash_sequence = hash256(struct.pack('<I', sequence))
    print(f"Debug: hashSequence: {hash_sequence.hex()}")
    outpoint = prevout
    script_code = bytes([0x19, 0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])
    print(f"Debug: scriptCode: {script_code.hex()}")
    outputs_bytes = b''.join(outputs)
    hash_outputs = hash256(outputs_bytes)
    print(f"Debug: hashOutputs: {hash_outputs.hex()}")
    sighash = compute_bip143_sighash(
        tx_version=2,
        hash_prevouts=hash_prevouts,
        hash_sequence=hash_sequence,
        outpoint=outpoint,
        script_code=script_code,
        value=utxo_amount,
        sequence=sequence,
        hash_outputs=hash_outputs,
        locktime=0,
        sighash_type=SIGHASH_ALL
    )
    print(f"Debug: Sighash: {sighash.hex()}")

    sk = ecdsa.SigningKey.from_string(
        private_key.to_bytes(),
        curve=ecdsa.SECP256k1,
        hashfunc=hashlib.sha256
    )

    # Sign with canonical signatures (low S values)
    while True:
        sig = sk.sign_digest_deterministic(
            sighash,
            sigencode=ecdsa.util.sigencode_der,
            extra_entropy=b''
        )

        # Parse the DER signature to check S value
        try:
            r, s = ecdsa.util.sigdecode_der(sig, sk.curve.order)
            # Check if S value is canonical (low)
            # SECP256k1 curve order
            curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if s <= curve_order // 2:
                # S is already canonical
                break
            else:
                # Make S canonical by using curve_order - s
                s = curve_order - s
                sig = ecdsa.util.sigencode_der(r, s, sk.curve.order)
                break
        except:
            # If parsing fails, try again with different entropy
            import os
            extra_entropy = os.urandom(32)
            sig = sk.sign_digest_deterministic(
                sighash,
                sigencode=ecdsa.util.sigencode_der,
                extra_entropy=extra_entropy
            )
            r, s = ecdsa.util.sigdecode_der(sig, sk.curve.order)
            if s <= curve_order // 2:
                break
            else:
                s = curve_order - s
                sig = ecdsa.util.sigencode_der(r, s, sk.curve.order)
                break

    sig_with_hashtype = sig + bytes([SIGHASH_ALL])
    return sig_with_hashtype, pub_key_bytes

def create_raw_transaction(utxo_txid: str, utxo_vout: int, utxo_amount: int,
                          utxo_addr: str, change_addr: str, fee: int, signal: str, private_key: PrivateKey) -> str:
    """Construct a raw SegWit transaction with proper signing"""
    signal_bytes = signal.encode('ascii')
    op_return_script = bytes([0x6a]) + encode_varint(len(signal_bytes)) + signal_bytes
    op_return_output = create_output(0, op_return_script)
    change_amount = utxo_amount - fee
    if change_amount < DUST_LIMIT:
        raise ValueError(f"Change amount {change_amount} below dust limit")
    change_addr_obj = P2wpkhAddress(change_addr)
    change_script = change_addr_obj.to_script_pub_key().to_bytes()
    change_output = create_output(change_amount, change_script)
    outputs = [op_return_output, change_output]
    signature, pub_key_bytes = sign_transaction_p2wpkh(
        private_key, utxo_txid, utxo_vout, utxo_amount, utxo_addr, outputs
    )
    tx_data = bytearray()
    tx_data.extend(struct.pack('<I', 2))
    tx_data.extend(bytes([0x00, 0x01]))
    tx_data.extend(encode_varint(1))
    tx_data.extend(bytes.fromhex(utxo_txid)[::-1])
    tx_data.extend(struct.pack('<I', utxo_vout))
    tx_data.extend(encode_varint(0))
    tx_data.extend(struct.pack('<I', 0xffffffff))
    tx_data.extend(encode_varint(len(outputs)))
    for output in outputs:
        tx_data.extend(output)
    tx_data.extend(encode_varint(2))
    tx_data.extend(encode_varint(len(signature)))
    tx_data.extend(signature)
    tx_data.extend(encode_varint(len(pub_key_bytes)))
    tx_data.extend(pub_key_bytes)
    tx_data.extend(struct.pack('<I', 0))
    return tx_data.hex()

def get_tx_id(raw_hex: str) -> str:
    """Calculate transaction ID from raw hex (non-witness serialization)"""
    raw_bytes = bytes.fromhex(raw_hex)
    non_witness = bytearray()
    non_witness.extend(raw_bytes[0:4])
    offset = 6
    in_count = raw_bytes[offset]
    non_witness.append(in_count)
    offset += 1
    for _ in range(in_count):
        non_witness.extend(raw_bytes[offset:offset+36])
        offset += 36
        script_len = raw_bytes[offset]
        non_witness.append(script_len)
        offset += 1
        if script_len > 0:
            non_witness.extend(raw_bytes[offset:offset+script_len])
            offset += script_len
        non_witness.extend(raw_bytes[offset:offset+4])
        offset += 4
    out_count = raw_bytes[offset]
    non_witness.append(out_count)
    offset += 1
    for _ in range(out_count):
        non_witness.extend(raw_bytes[offset:offset+8])
        offset += 8
        script_len = raw_bytes[offset]
        non_witness.append(script_len)
        offset += 1
        non_witness.extend(raw_bytes[offset:offset+script_len])
        offset += script_len
    non_witness.extend(raw_bytes[-4:])
    txid = hash256(bytes(non_witness))
    return txid[::-1].hex()

def broadcast_raw_tx(raw_hex: str):
    """Broadcast transaction to testnet"""
    headers = {'Content-Type': 'text/plain'}
    urls = [
        "https://mempool.space/testnet/api/tx",
        "https://blockstream.info/testnet/api/tx"
    ]
    for url in urls:
        try:
            r = requests.post(url, data=raw_hex, headers=headers, timeout=20)
            if r.status_code in (200, 201):
                return True, r.text.strip()
            else:
                print(f"Failed on {url}, status {r.status_code}, text: {r.text}")
        except Exception as e:
            print(f"Exception on {url}: {e}")
    return False, "Failed to broadcast"

def decode_transaction(raw_hex: str):
    """Decode and display transaction details for debugging"""
    print("\n=== Transaction Debug Info ===")
    raw = bytes.fromhex(raw_hex)
    version = struct.unpack('<I', raw[0:4])[0]
    print(f"Version: {version}")
    if raw[4:6] == b'\x00\x01':
        print("SegWit transaction detected")
        offset = 6
        in_count = raw[offset]
        offset += 1
        for _ in range(in_count):
            offset += 36
            script_len = raw[offset]
            offset += 1 + script_len + 4
        out_count = raw[offset]
        offset += 1
        for _ in range(out_count):
            offset += 8
            script_len = raw[offset]
            offset += 1 + script_len
        witness_count = raw[offset]
        offset += 1
        if witness_count > 0:
            sig_len = raw[offset]
            offset += 1
            signature = raw[offset:offset+sig_len]
            print(f"Signature length: {sig_len} bytes")
            print(f"Signature (hex): {signature.hex()}")
            offset += sig_len
            pubkey_len = raw[offset]
            offset += 1
            pubkey = raw[offset:offset+pubkey_len]
            print(f"Public key: {pubkey.hex()}")

def main():
    setup('testnet')
    parser = argparse.ArgumentParser(description="Guardian Lock/Unlock transaction builder")
    parser.add_argument("--wif", required=True, help="WIF private key controlling UTXO")
    parser.add_argument("--utxo-txid", required=True, help="UTXO transaction ID")
    parser.add_argument("--utxo-vout", type=int, required=True, help="UTXO output index")
    parser.add_argument("--utxo-sats", type=int, required=True, help="UTXO value in satoshis")
    parser.add_argument("--utxo-addr", required=True, help="P2WPKH address of the UTXO")
    parser.add_argument("--to-addr", required=True, help="P2WPKH change address")
    parser.add_argument("--fee-sats", type=int, required=True, help="Transaction fee in satoshis")
    parser.add_argument("--nonce", type=int, default=1, help="Monotonic nonce for signal")
    parser.add_argument("--lock", action="store_true", help="Signal Lock")
    parser.add_argument("--unlock", action="store_true", help="Signal Unlock")
    parser.add_argument("--broadcast", action="store_true", help="Broadcast the transaction")
    parser.add_argument("--debug", action="store_true", help="Show debug information")
    args = parser.parse_args()
    if args.lock and args.unlock:
        parser.error("Cannot specify both --lock and --unlock")
    if not args.lock and not args.unlock:
        parser.error("Must specify either --lock or --unlock")
    try:
        priv = PrivateKey.from_wif(args.wif)
        addr = priv.get_public_key().get_address()
        signal = create_guardian_signal(args.lock, args.nonce)
        print(f"\nGuardian signal: {signal}")
        print(f"Signal length: {len(signal.encode('ascii'))} bytes")
        print(f"UTXO: {args.utxo_txid}:{args.utxo_vout} ({args.utxo_sats} sats)")
        print(f"Fee: {args.fee_sats} sats")
        print(f"Change: {args.utxo_sats - args.fee_sats} sats to {args.to_addr}")
        raw_hex = create_raw_transaction(
            args.utxo_txid, args.utxo_vout, args.utxo_sats,
            args.utxo_addr, args.to_addr, args.fee_sats, signal, priv
        )
        print(f"\nTransaction size: {len(raw_hex)//2} bytes")
        print(f"Estimated vBytes: {(len(raw_hex)//2 * 3 + 3) // 4}")
        txid = get_tx_id(raw_hex)
        print(f"Transaction ID: {txid}")
        if args.debug:
            decode_transaction(raw_hex)
        print(f"\nRaw transaction hex:\n{raw_hex}")
        if args.broadcast:
            print("\nBroadcasting transaction...")
            ok, info = broadcast_raw_tx(raw_hex)
            if ok:
                print(f"✓ Broadcast successful!")
                print(f"  Transaction ID: {info}")
                print(f"  View at: https://mempool.space/testnet/tx/{info}")
            else:
                print(f"✗ Broadcast failed: {info}")
        else:
            print("\nTransaction created but not broadcast. Use --broadcast to send it.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
