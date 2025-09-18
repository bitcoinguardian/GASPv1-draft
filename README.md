# Guardian Signal Tools

Command line tools for creating and managing Guardian Address signals for the Guardian Address BIP implementation.

A wallet implementation of this draft implementing the protocol exists at https://github.com/bitcoinguardian/electrum

## Overview

These tools help create the Guardian Address transactions required for the Guardian Address protocol - a Bitcoin coercion resistance mechanism that uses on-chain signaling to lock/unlock wallets remotely.

## Files

- `guardian_signal.py` - Creates and broadcasts Guardian lock/unlock transactions
- `generate_guardian_address.py` - Generates new Guardian addresses with private keys

## Requirements

Install dependencies:

```bash
pip install python-bitcoinutils ecdsa requests bitcoin
```

## Usage

### 1. Generate Guardian Address

First, create a new Guardian address and private key:

```bash
python3 generate_guardian_address.py
```

This outputs:
- WIF private key (keep secure and separate from spending wallets)
- Testnet P2WPKH address (your Guardian Address)

**Security Note**: The Guardian private key must be stored separately from your spending wallet keys to prevent coercion attacks.

### 2. Fund Guardian Address

Send some testnet Bitcoin to the generated Guardian address. You need small amounts (1000-5000 sats) for signal transactions.

### 3. Create Guardian Signals

Use `guardian_signal.py` to create lock/unlock signals:

#### Instantiate Guardian (first use)
```bash
python3 guardian_signal.py \
  --wif <guardian_private_key_wif> \
  --utxo-txid <funding_txid> \
  --utxo-vout <funding_vout> \
  --utxo-sats <funding_amount> \
  --utxo-addr <guardian_address> \
  --to-addr <guardian_address> \
  --fee-sats 1000 \
  --nonce 1 \
  --unlock \
  --broadcast
```

#### Lock Wallet (emergency use)
```bash
python3 guardian_signal.py \
  --wif <guardian_private_key_wif> \
  --utxo-txid <previous_txid> \
  --utxo-vout 1 \
  --utxo-sats <remaining_amount> \
  --utxo-addr <guardian_address> \
  --to-addr <guardian_address> \
  --fee-sats 1000 \
  --nonce 2 \
  --lock \
  --broadcast
```

#### Unlock Wallet
```bash
python3 guardian_signal.py \
  --wif <guardian_private_key_wif> \
  --utxo-txid <lock_txid> \
  --utxo-vout 1 \
  --utxo-sats <remaining_amount> \
  --utxo-addr <guardian_address> \
  --to-addr <guardian_address> \
  --fee-sats 1000 \
  --nonce 3 \
  --unlock \
  --broadcast
```

### Parameters

- `--wif`: WIF private key controlling the Guardian address
- `--utxo-txid`: Transaction ID of UTXO to spend
- `--utxo-vout`: Output index (usually 1 for change output)
- `--utxo-sats`: Amount in the UTXO (in satoshis)
- `--utxo-addr`: Guardian address (P2WPKH format)
- `--to-addr`: Change address (same as Guardian address)
- `--fee-sats`: Transaction fee (recommend 1000+ sats for reliable confirmation)
- `--nonce`: Monotonic counter (must increment for each signal)
- `--lock` / `--unlock`: Signal type
- `--broadcast`: Actually send the transaction (omit for testing)

## Signal Format

Guardian signals embed this data in OP_RETURN outputs:

```
guardv1.Lock=<true|false>#<nonce>
```

Examples:
- `guardv1.Lock=false#1` - Unlock/instantiation signal
- `guardv1.Lock=true#2` - Lock signal
- `guardv1.Lock=false#3` - Unlock signal

## Pre-signed Transactions

For emergency use, you can create pre-signed lock transactions:

1. Create the transaction without `--broadcast`
2. Save the raw transaction hex
3. Store it securely but separate from keys
4. Broadcast later using: `bitcoin-cli sendrawtransaction <hex>`

This allows locking wallets even without access to the Guardian private key.

## Security Considerations

- **Key Separation**: Guardian keys must be physically separate from spending wallet keys
- **Nonce Management**: Always increment nonce for each new signal
- **Fee Rates**: Use sufficient fees (20+ sat/vB) to ensure timely confirmation
- **UTXO Tracking**: Keep track of which UTXO is available for the next signal
- **Pre-signing**: Create emergency lock transactions in advance

## Signal Boxes

For increased reliability, create multiple transactions with the same nonce but different fee rates:

```bash
# Low fee version
python3 guardian_signal.py --fee-sats 1000 --nonce 2 --lock

# High fee version
python3 guardian_signal.py --fee-sats 3000 --nonce 2 --lock
```

Only broadcast one - they're mutually exclusive but provide fee flexibility.

## Testnet vs Mainnet

These tools are configured for **testnet only**. For mainnet use:

1. Change `setup('testnet')` to `setup('mainnet')` in `guardian_signal.py`
2. Change `SelectParams("testnet")` to `SelectParams("mainnet")` in `generate_guardian_address.py`
3. Use mainnet UTXOs and addresses
4. **Exercise extreme caution** - test thoroughly on testnet first

## Troubleshooting

**Transaction not confirming**: Increase fee rate or use RBF (though Guardian protocol requires non-RBF)

**Invalid UTXO**: Check that the UTXO hasn't been spent and the amount is correct

**Nonce errors**: Ensure nonce is higher than the previous signal's nonce

**Address mismatch**: Verify the private key corresponds to the Guardian address

## Integration

These signals work with Guardian Address compatible wallets like the Guardian plugin for Electrum. Wallets monitor the Guardian address and disable spending when lock signals are detected.

## License

MIT License - same as the Guardian Address BIP implementation.
