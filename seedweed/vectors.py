import random

import seedweed


def random_bytes(rng, length):
    return bytes([rng.randint(0, 255) for _ in range(length)])


P256 = seedweed.P256
H = seedweed.H


class Parameters:
    def __init__(self):
        # independent DRNG
        rng = random.Random(2020)

        self.seeds = [
            random_bytes(rng, 32),
            random_bytes(rng, 32),
            bytes([0] * 32),
            (P256.order + 1).to_bytes(32, "big"),
            bytes([1] * 32),
            bytes([0xFF] * 32),
            H(b"the dicekey method"),
        ]

        self.rp_ids = [
            "solokeys.com",
            "dicekeys.com",
            "fidoalliance.org",
            "example.com",
        ]

        self.nonces = [random_bytes(rng, 32) for _ in range(4)]

        self.extra_states = [
            b"",
            b"canonical encoding",
            b"sunny side up",
            random_bytes(rng, 256),
        ]


def generate(parameters=Parameters()):

    print("seed,rp_id,credential_id,pub_key,signature")

    import itertools

    for extra_state, seed, rp_id, nonce in itertools.product(
        parameters.extra_states,
        parameters.seeds,
        parameters.rp_ids,
        parameters.nonces,
    ):
        rp_id_hash = H(rp_id.encode())

        credential_id = seedweed.credential_id_from_seed_nonce_rpidhash(
            seed,
            nonce,
            rp_id_hash,
            extra_state,
        )

        assert seedweed.validate_credential_id(seed, credential_id, rp_id_hash)

        mac = credential_id[-32:]

        scalar, point, keypair, iterations = seedweed.keypair_from_seed_mac(seed, mac)
        # TODO: we really need some examples with >1 iterations,
        # ideally even some rare >2 case
        assert iterations == 1

        # X big-endian 32B || Y big-endian 32B
        pub_key_uncompressed = keypair.verifying_key._raw_encode()

        signature = keypair.sign_deterministic(b"seedweed")

        print(
            f"{seed.hex()},{rp_id},{credential_id.hex()},",
            f"{pub_key_uncompressed.hex()},{signature.hex()}",
        )
