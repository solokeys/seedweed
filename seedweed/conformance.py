import hashlib

from . import reference as seedweed

H = seedweed.H


def verify_make_credential(
    testvector,
    authnr_credential_id,
    authnr_credential_public_key,
    attested_data,
):

    seed = testvector["seed"]
    rp_id_hash = H(testvector["rp_id"].encode())
    # check credential ID is well-formed
    seedweed.validate_credential_id(
        testvector["seed"],
        authnr_credential_id,
        rp_id_hash,
    )

    authnr_nonce, _, authnr_mac = seedweed.nonce_extstate_mac_from_credential_id(
        authnr_credential_id
    )

    credential_id = seedweed.credential_id_from_seed_nonce_rpidhash(
        seed, authnr_nonce, rp_id_hash
    )

    # tests mac == authnr_mac
    assert credential_id == authnr_credential_id

    _, _, keypair, _ = seedweed.keypair_from_seed_mac(seed, authnr_mac)

    # tests that the correct public key is generated,
    # implying correct secret key, implying correct number of iterations (2 in test case 37)
    # (credentials don't need to be self-signed, typical authenticator uses direct attestation)
    assert testvector["pub_key"] == authnr_credential_public_key


def verify_get_assertion(
    testvector,
    authnr_signature,
    signed_data,
):
    seed = testvector["seed"]
    mac = testvector["mac"]

    _, _, keypair, _ = seedweed.keypair_from_seed_mac(seed, mac)

    # check signature, raises `BadSignatureError: Signature verification failed` else
    keypair.verifying_key.verify(authnr_signature, signed_data, hashfunc=hashlib.sha256)
