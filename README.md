# Reference implementation and test vectors for DiceKey's "Seeding WebAuthN" specification

<b>SEED</b>ing <b>WE</b>bAuthN Cr<b>ED</b>entials (weeds out implementation bugs)

Spec: <https://github.com/dicekeys/seeding-webauthn>.

Contains:
- `keypair_from_seed_mac` specifying how to generate the P256 keypairs
- `credential_id_from_seed_nonce_rpidhash`, specifying how to serialize credentials
- `validate_credential_id` specifying how to verify a received credential ID is valid
- `nonce_extstate_mac_from_credential_id`, specifying how to deserialize credential IDs
- [test vectors](data/test-vectors.csv) (can easily adapt, uses independent seeded DRBG)

Does not contain:
- construction of nonce / unique ID from `(seed, rp_id, user_id, entropy)` quadruples;
  this is left to the authenticator implementation by the specification.

The signatures are over `b"seedweed"`.


## Minimum checks for authenticator spec compliance

1. Authenticator accepts credential IDs from test vector file for given (seed, RP ID)
1. Authenticator derives same keypair, in particular:

    - same COSE public key
    - would verify the signatures in the test vector file


## On test vectors

The authenticator has leeway on:
- how to generate a nonce ("uniqueId") for its credentials
- whether to include "extState" in its (generated) credential IDs
- whether to follow [RFC 6979](https://tools.ietf.org/html/rfc6979), i.e., deterministic signatures

However:
- given (seed, credentialID), the P256 keypair is determined, and
- additionally given rpIdHash, appropriate credential binding can be verified

P256 public keys are serialized here as (X, Y) coordinates, each as zero-padded 32 byte big-endian.


## Installation

To install, need Python >=3.6, then: `pip install git+https://github.com/nickray/seedweed`

Once done, there should be a command `generate-seedweed-test-vectors` you can run that
recreates the test vectors. Modifying the [Parameters](seedweed/vectors.py#L14) allows generating
more test vectors, as needed.


## Development

Many ways, one is to `make setup` and then `source venv/bin/activate`.

Uses `flit` for packaging as it seems least-effort (`flit build`, `flit install`).


## Contributing

Please save files with UNIX-style line endings, and run `make check` to enforce
basic consistency (`make fix` can automatically fix most issues).
