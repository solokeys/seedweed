import hashlib

from . import reference as seedweed

H = seedweed.H


def verify_make_credential(
    testvector,
    authnr_credential_id,
    authnr_public_key,
    # attested_data,
):

    seed = testvector["seed"]
    rp_id_hash = H(testvector["rp_id"].encode())

    # check credential ID is well-formed
    seedweed.validate_credential_id(
        testvector["seed"],
        authnr_credential_id,
        rp_id_hash,
    )

    (
        authnr_nonce,
        authnr_ext_state,
        authnr_mac,
    ) = seedweed.nonce_extstate_mac_from_credential_id(authnr_credential_id)

    credential_id = seedweed.credential_id_from_seed_nonce_rpidhash(
        seed, authnr_nonce, rp_id_hash, authnr_ext_state
    )

    # tests authnr_mac == correct
    assert credential_id == authnr_credential_id

    _, _, keypair, _ = seedweed.keypair_from_seed_mac(seed, authnr_mac)
    expected_public_key = keypair.verifying_key._raw_encode()

    # tests that the correct public key is generated
    # note that the authenticator is under no obligation to use the same nonce
    assert expected_public_key == authnr_public_key, (
        expected_public_key.hex(),
        authnr_public_key.hex(),
    )


def verify_get_assertion(
    testvector,
    authnr_signature,
    authnr_signed_data,
):
    seed = testvector["seed"]
    mac = testvector["mac"]

    _, _, keypair, _ = seedweed.keypair_from_seed_mac(seed, mac)

    # check signature, raises `BadSignatureError: Signature verification failed` else
    keypair.verifying_key.verify(
        authnr_signature, authnr_signed_data, hashfunc=hashlib.sha256
    )
