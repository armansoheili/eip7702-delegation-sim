# eip7702-delegation-sim

EIP-7702 (Pectra) delegation simulator in pure Python — no dependencies.

An EOA can temporarily act like a smart contract: a signed authorization
tuple `(chain_id, delegate address, nonce)` sets the account's code to the
delegation indicator `0xef0100 || delegate_address`, so calls to the
account are forwarded to the delegate contract. Delegating to the zero
address revokes it.

## What it models

- `Authorization` — the (chain_id, address, nonce) tuple
- `Account` — an EOA that signs authorizations and holds delegation code
- `Network.apply_authorization()` — every check a client performs:
  chain id match, nonce match, no pre-existing non-delegation code,
  signature validity, delegate must be a known contract
- `Network.execute_batch()` — batched calls through the delegate contract,
  debited from the account balance
- Revocation via delegation to the zero address

Signatures here are a SHA-256 stand-in keyed by the account's secret
(real EIP-7702 uses ECDSA over secp256k1 with address recovery); the
validation logic — chain id, nonce, signature — is identical.

## Run

```sh
python3 eip7702.py            # delegate -> batch -> revoke demo
python3 eip7702.py --test     # doctests
```
