"""EIP-7702 delegation simulator in pure Python.

EIP-7702 (Pectra) lets an externally owned account (EOA) temporarily act
like a smart contract: a signed *authorization tuple* -- (chain_id,
delegate address, nonce) -- sets the account's code to a tiny delegation
indicator ``0xef0100 || delegate_address``. Calls to the account are then
forwarded to the delegate contract, so the EOA gains smart-account powers
(batch execution, sponsored gas, ...) without giving up its key. Pointing
the delegation at the zero address revokes it.

This module simulates that lifecycle. Real EIP-7702 signatures are ECDSA
over secp256k1 with the signer's address recovered from the signature;
here signing is a SHA-256 stand-in keyed by the account's secret, which
keeps the simulator dependency-free while preserving the exact checks a
client performs: chain id, nonce, and signature validity.

>>> net = Network(chain_id=1)
>>> alice = net.create_account("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
...                            secret=b"alice-secret", balance=10_000)
>>> batcher = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
>>> net.register_contract(batcher, "BatchExecutor")
>>> auth = alice.authorize(net.chain_id, batcher)
>>> _ = net.apply_authorization(alice, auth)
>>> alice.code.hex()
'ef0100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
>>> alice.nonce
1
>>> net.delegated_to(alice)
'0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
>>> net.execute_batch(alice, [("0xcccccccccccccccccccccccccccccccccccccccc", 100, "0x"),
...                            ("0xdddddddddddddddddddddddddddddddddddddddd", 250, "0x")])
[('0xcccccccccccccccccccccccccccccccccccccccc', 100), ('0xdddddddddddddddddddddddddddddddddddddddd', 250)]
>>> alice.balance
9650
>>> # Revoke: delegate to the zero address and the code is wiped.
>>> _ = net.apply_authorization(alice, alice.authorize(net.chain_id, ZERO_ADDRESS))
>>> alice.code
b''
>>> net.delegated_to(alice) is None
True
>>> # Wrong chain id, stale nonce, or a tampered signature all fail.
>>> net.apply_authorization(alice, alice.authorize(999, batcher))
Traceback (most recent call last):
...
ValueError: authorization chain_id 999 does not match network chain_id 1
>>> stale = Authorization(net.chain_id, batcher, nonce=0)
>>> net.apply_authorization(alice, stale, signature=alice.sign(stale))
Traceback (most recent call last):
...
ValueError: authorization nonce 0 does not match account nonce 2
>>> good = alice.authorize(net.chain_id, batcher)
>>> net.apply_authorization(alice, good, signature="00" * 32)
Traceback (most recent call last):
...
ValueError: invalid authorization signature
>>> # An account whose code is real contract code cannot be delegated.
>>> mallory = net.create_account("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
...                              secret=b"mallory-secret")
>>> mallory.code = b"\\x60\\x00\\x60\\x00"  # arbitrary non-delegation code
>>> net.apply_authorization(mallory, mallory.authorize(net.chain_id, batcher))
Traceback (most recent call last):
...
ValueError: account already has non-delegation code
"""

import hashlib

__all__ = [
    "Authorization",
    "Account",
    "Network",
    "DELEGATION_PREFIX",
    "ZERO_ADDRESS",
    "delegation_code",
    "normalize_address",
]

DELEGATION_PREFIX = bytes.fromhex("ef0100")
ZERO_ADDRESS = "0x" + "00" * 20


def normalize_address(address):
    """Validate and lowercase a 20-byte hex address.

    >>> normalize_address("0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD")
    '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'
    >>> normalize_address("not-an-address")
    Traceback (most recent call last):
    ...
    ValueError: invalid address: 'not-an-address'
    """
    if (
        not isinstance(address, str)
        or len(address) != 42
        or not address.startswith("0x")
    ):
        raise ValueError(f"invalid address: {address!r}")
    try:
        bytes.fromhex(address[2:])
    except ValueError:
        raise ValueError(f"invalid address: {address!r}") from None
    return address.lower()


def delegation_code(delegate):
    """The code an EOA carries while delegated to ``delegate``.

    >>> delegation_code("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").hex()
    'ef0100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    """
    return DELEGATION_PREFIX + bytes.fromhex(normalize_address(delegate)[2:])


class Authorization:
    """One EIP-7702 authorization tuple: (chain_id, address, nonce)."""

    def __init__(self, chain_id, address, nonce):
        self.chain_id = int(chain_id)
        self.address = normalize_address(address)
        self.nonce = int(nonce)

    def signing_payload(self):
        return f"{self.chain_id}:{self.address}:{self.nonce}".encode()

    def __repr__(self):
        return (
            f"Authorization(chain_id={self.chain_id}, "
            f"address={self.address!r}, nonce={self.nonce})"
        )


class Account:
    """An EOA that can sign authorizations and hold delegation code."""

    def __init__(self, address, secret, balance=0):
        self.address = normalize_address(address)
        self.secret = bytes(secret)
        self.balance = int(balance)
        self.nonce = 0
        self.code = b""

    def authorize(self, chain_id, delegate):
        """Build the authorization for the account's current nonce."""
        return Authorization(chain_id, delegate, self.nonce)

    def sign(self, authorization):
        """Toy signature stand-in for ECDSA recovery (see module docstring)."""
        return hashlib.sha256(self.secret + authorization.signing_payload()).hexdigest()

    def verify(self, authorization, signature):
        return signature == self.sign(authorization)


class Network:
    """A single chain that applies authorizations and runs batch calls."""

    def __init__(self, chain_id):
        self.chain_id = int(chain_id)
        self.accounts = {}
        self.contracts = {}  # delegate address -> human-readable name

    def create_account(self, address, secret, balance=0):
        account = Account(address, secret, balance)
        self.accounts[account.address] = account
        return account

    def register_contract(self, address, name):
        self.contracts[normalize_address(address)] = name

    def delegated_to(self, account):
        """The delegate address, or None if the account is not delegated."""
        if account.code.startswith(DELEGATION_PREFIX) and len(account.code) == 23:
            return "0x" + account.code[3:].hex()
        return None

    def delegated_accounts(self):
        """(address, delegate) pairs for every account currently delegated.

        >>> net = Network(chain_id=1)
        >>> alice = net.create_account("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ...                            secret=b"alice-secret")
        >>> bob = net.create_account("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ...                          secret=b"bob-secret")
        >>> batcher = "0xcccccccccccccccccccccccccccccccccccccccc"
        >>> net.register_contract(batcher, "BatchExecutor")
        >>> net.delegated_accounts()
        []
        >>> code = net.apply_authorization(alice, alice.authorize(1, batcher))
        >>> code == delegation_code(batcher)
        True
        >>> net.delegated_accounts()
        [('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '0xcccccccccccccccccccccccccccccccccccccccc')]
        >>> net.apply_authorization(alice, alice.authorize(1, ZERO_ADDRESS))
        b''
        >>> net.delegated_accounts()
        []
        """
        return [
            (address, self.delegated_to(account))
            for address, account in self.accounts.items()
            if self.delegated_to(account) is not None
        ]

    def apply_authorization(self, account, authorization, signature=None):
        """Apply one authorization tuple, performing every client check.

        A missing signature is signed by the account itself (the common
        case in tests and demos); pass an explicit signature to simulate a
        signature arriving over the wire.
        """
        if authorization.chain_id != self.chain_id:
            raise ValueError(
                f"authorization chain_id {authorization.chain_id} "
                f"does not match network chain_id {self.chain_id}"
            )
        if authorization.nonce != account.nonce:
            raise ValueError(
                f"authorization nonce {authorization.nonce} "
                f"does not match account nonce {account.nonce}"
            )
        if account.code and not account.code.startswith(DELEGATION_PREFIX):
            raise ValueError("account already has non-delegation code")
        if signature is None:
            signature = account.sign(authorization)
        if not account.verify(authorization, signature):
            raise ValueError("invalid authorization signature")
        if authorization.address == ZERO_ADDRESS:
            account.code = b""  # revocation: wipe the delegation indicator
        else:
            if authorization.address not in self.contracts:
                raise ValueError(
                    f"delegate {authorization.address} is not a known contract"
                )
            account.code = delegation_code(authorization.address)
        account.nonce += 1
        return account.code

    def execute_batch(self, account, calls):
        """Run several calls through the account's delegate contract.

        ``calls`` is a list of (to, value, data) triples. Only a delegated
        account can batch; value is debited from the account's balance.
        Returns the executed (to, value) pairs.
        """
        if self.delegated_to(account) is None:
            raise ValueError("account is not delegated; cannot batch calls")
        executed = []
        for to, value, _data in calls:
            if value > account.balance:
                raise ValueError(
                    f"insufficient balance for call to {to}: "
                    f"needs {value}, has {account.balance}"
                )
            account.balance -= value
            executed.append((normalize_address(to), value))
        return executed


def demo():
    """Walk through delegate -> batch -> revoke on chain 1."""
    net = Network(chain_id=1)
    alice = net.create_account(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", secret=b"alice-secret",
        balance=5_000,
    )
    batcher = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    net.register_contract(batcher, "BatchExecutor")
    net.apply_authorization(alice, alice.authorize(1, batcher))
    print(f"delegated to {net.delegated_to(alice)}, nonce={alice.nonce}")
    print("batch:", net.execute_batch(alice, [
        ("0xcccccccccccccccccccccccccccccccccccccccc", 1_000, "0x"),
        ("0xdddddddddddddddddddddddddddddddddddddddd", 500, "0x"),
    ]))
    print(f"balance after batch: {alice.balance}")
    net.apply_authorization(alice, alice.authorize(1, ZERO_ADDRESS))
    print(f"after revoke: code={alice.code!r}, nonce={alice.nonce}")


if __name__ == "__main__":
    import sys

    if "--test" in sys.argv:
        import doctest

        raise SystemExit(doctest.testmod(verbose=False).failed)
    demo()
