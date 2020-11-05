import csv
import pathlib
import random

from . import reference as seedweed


def load(shortlist=False, seed=0):
    data_file = pathlib.Path(__file__).parent / "test-vectors.csv"
    reader = csv.DictReader(open(data_file))
    data = []
    for row in reader:
        credential_id = bytes.fromhex(row["credential_id"])
        nonce, extstate, mac = seedweed.nonce_extstate_mac_from_credential_id(
            credential_id
        )
        data.append(
            {
                "seed": bytes.fromhex(row["seed"]),
                "rp_id": row["rp_id"],
                "nonce": nonce,
                "mac": mac,
                "credential_id": credential_id,
                "secret_scalar": row["sec_scalar"],
                "pub_key": row["pub_key"],
                "ext_state": extstate,
                "iterations": int(row["iterations"]),
            }
        )

    if shortlist:
        random.seed(seed)
        only_one_iteration = [datum for datum in data if datum["iterations"] == 1]
        more_than_one_iterations = [datum for datum in data if datum["iterations"] > 1]
        has_empty_ext_state = [datum for datum in data if len(datum["ext_state"]) == 0]
        has_nontrivial_ext_state = [
            datum for datum in data if len(datum["ext_state"]) > 0
        ]

        data = []
        data += random.sample(only_one_iteration, 1)
        data += random.sample(more_than_one_iterations, 1)
        data += random.sample(has_empty_ext_state, 1)
        data += random.sample(has_nontrivial_ext_state, 1)
        data += random.sample(data, 4)
    return data


def random_bytes(rng, length):
    return rng.getrandbits(8 * length).to_bytes(length, "little")


P256 = seedweed.P256
H = seedweed.H


class Parameters:
    def __init__(self):
        # independent DRNG
        rng = random.Random(2020)

        self.seeds = [
            random_bytes(rng, 32),
            bytes.fromhex(
                "dd2ca3b88f9491c042fcc04c5e732e9f6fd9c0eb6f3b99cddd4ae96d661ada2c"
            ),
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

        self.nonces = [random_bytes(rng, 32) for _ in range(4)] + [
            bytes.fromhex(
                "8b911917c0b74f77e6fb819d6a8034a94f0fca487cacb41e89235c5c5220947b"
            )
        ]
        self.extra_states = [
            b"",
            b"sunny side up",
            random_bytes(rng, 256),
        ]


def generate(parameters=Parameters()):

    print(
        "".join(
            (
                "seed,rp_id,nonce,mac,credential_id,sec_scalar,pub_key,",
                "example_signature_for_seedweed,iterations",
            )
        )
    )

    import itertools

    max_iterations = 0
    for extra_state, seed, nonce, rp_id in itertools.product(
        parameters.extra_states,
        parameters.seeds,
        parameters.nonces,
        parameters.rp_ids,
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
        if iterations > max_iterations:
            max_iterations = iterations
        assert 1 <= scalar < P256.order

        # X big-endian 32B || Y big-endian 32B
        pub_key_uncompressed = keypair.verifying_key._raw_encode()

        signature = keypair.sign_deterministic(b"seedweed")

        nonce, ext_state, mac = seedweed.nonce_extstate_mac_from_credential_id(
            credential_id
        )
        # reformatted_credential_id = ":".join(
        #     ["1", nonce.hex(), mac.hex(), ext_state.hex(), mac.hex()]
        # )

        print(
            "".join(
                (
                    f"{seed.hex()},{rp_id},{nonce.hex()},{mac.hex()},{credential_id.hex()},",
                    f"{scalar},{pub_key_uncompressed.hex()},{signature.hex()},{iterations}",
                )
            )
        )

    # have test cases to cover the 1 in 4 billion case
    assert 1 < max_iterations  # <= 2
