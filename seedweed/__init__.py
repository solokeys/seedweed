"""Seeded WebAuthn Credentials: reference implementation"""

__version__ = "1.0-pre"

import hashlib
import hmac

import ecdsa

P256 = ecdsa.NIST256p

VERSION = bytes([1])


def assert_bytes(value):
    assert isinstance(value, bytes), value


def assert_32_bytes(value):
    assert_bytes(value)
    assert len(value) == 32, value


def assert_credential_id(credential_id: bytes):
    assert_bytes(credential_id)
    assert 65 <= len(credential_id) <= 65 + 256
    assert credential_id[:1] == VERSION


def H(data: bytes) -> bytes:
    assert_bytes(data)

    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()


def HMAC(key: bytes, data: bytes) -> bytes:
    assert_32_bytes(key)
    assert_bytes(data)

    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(data)
    return mac.digest()


def keypair_from_seed_mac(seed: bytes, mac: bytes) -> ecdsa.SigningKey:
    assert_32_bytes(seed)
    assert_32_bytes(mac)

    P256 = ecdsa.NIST256p

    candidate_bytes = HMAC(seed, mac)
    candidate_scalar = int.from_bytes(candidate_bytes, "little")
    iterations = 1
    while not (0 < candidate_scalar < P256.order):
        candidate_bytes = HMAC(seed, candidate_bytes)
        candidate_scalar = int.from_bytes(candidate_bytes, "little")
        iterations += 1

    secret_scalar = candidate_scalar
    public_point = secret_scalar * P256.generator
    keypair = ecdsa.SigningKey.from_secret_exponent(secret_scalar, P256)

    return secret_scalar, public_point, keypair, iterations


def credential_id_from_seed_nonce_rpidhash(
    seed: bytes, nonce: bytes, rp_id_hash: bytes, ext_state: bytes = bytes()
) -> bytes:
    assert_32_bytes(seed)
    assert_32_bytes(nonce)
    assert_32_bytes(rp_id_hash)
    assert_bytes(ext_state)
    assert len(ext_state) <= 256

    message = VERSION + nonce + ext_state
    bound_message = rp_id_hash + message
    mac = HMAC(seed, bound_message)
    credential_id = message + mac
    return credential_id


def nonce_extstate_mac_from_credential_id(credential_id: bytes):
    assert_credential_id(credential_id)
    nonce = credential_id[1:33]
    ext_state = credential_id[33:-32]
    mac = credential_id[-32:]

    return nonce, ext_state, mac


def validate_credential_id(seed: bytes, credential_id: bytes, rp_id_hash: bytes):
    assert_32_bytes(seed)
    nonce, ext_state, mac = nonce_extstate_mac_from_credential_id(credential_id)

    message = VERSION + nonce + ext_state
    calculated_mac = HMAC(seed, rp_id_hash + message)

    assert calculated_mac == mac, f"{calculated_mac} != {mac}"
    return True
