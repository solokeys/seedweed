import csv
import pathlib
import random

from . import reference as seedweed

P256 = seedweed.P256
H = seedweed.H


def random_bytes(rng, length):
    return rng.getrandbits(8 * length).to_bytes(length, "little")


def load(shortlist=False, seed=0):
    filename = pathlib.Path(__file__).parent / "test-vectors.csv"
    reader = csv.DictReader(open(filename))
    vectors = []
    for row in reader:
        credential_id = bytes.fromhex(row["credential_id"])
        nonce, extstate, mac = seedweed.nonce_extstate_mac_from_credential_id(
            credential_id
        )
        vectors.append(
            {
                "seed": bytes.fromhex(row["seed"]),
                "rp_id": row["rp_id"],
                "nonce": nonce,
                "mac": mac,
                "credential_id": credential_id,
                "secret_scalar": row["secret_scalar"],
                "public_key": row["public_key"],
                "ext_state": extstate,
                "iterations": int(row["iterations"]),
            }
        )

    if shortlist:
        vectors = select_shortlist(vectors, seed) + random.sample(vectors, 4)
    return vectors


def select_shortlist(vectors, seed=0):
    only_one_iteration = [vector for vector in vectors if vector["iterations"] == 1]
    more_than_one_iterations = [
        vector for vector in vectors if vector["iterations"] > 1
    ]
    # more_than_two_iterations = [vector for vector in vectors if vector["iterations"] > 2]
    has_empty_ext_state = [
        vector for vector in vectors if len(vector["ext_state"]) == 0
    ]
    has_nontrivial_ext_state = [
        vector for vector in vectors if len(vector["ext_state"]) > 0
    ]

    vectors = []
    vectors += random.sample(only_one_iteration, 1)
    vectors += random.sample(more_than_one_iterations, 1)
    # vectors += random.sample(more_than_two_iterations, 1)
    vectors += random.sample(has_empty_ext_state, 1)
    vectors += random.sample(has_nontrivial_ext_state, 1)

    return vectors


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


def generate(parameters=Parameters(), print_to_stdout=True, return_vectors=False):
    import itertools

    if print_to_stdout:
        print(
            "".join(
                (
                    "seed,rp_id,nonce,mac,credential_id,secret_scalar,public_key,",
                    "example_signature_for_seedweed,iterations",
                )
            )
        )

    max_iterations = 0
    vectors = []
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

        (
            secret_scalar,
            public_point,
            keypair,
            iterations,
        ) = seedweed.keypair_from_seed_mac(seed, mac)
        # TODO: we really need some examples with >1 iterations,
        # ideally even some rare >2 case
        if iterations > max_iterations:
            max_iterations = iterations
        assert 1 <= secret_scalar < P256.order

        # X big-endian 32B || Y big-endian 32B
        public_key = keypair.verifying_key._raw_encode()

        signature = keypair.sign_deterministic(b"seedweed")

        nonce, ext_state, mac = seedweed.nonce_extstate_mac_from_credential_id(
            credential_id
        )
        # reformatted_credential_id = ":".join(
        #     ["1", nonce.hex(), mac.hex(), ext_state.hex(), mac.hex()]
        # )
        vector = {
            "seed": seed,
            "rp_id": rp_id,
            "nonce": nonce,
            "mac": mac,
            "credential_id": credential_id,
            "secret_scalar": secret_scalar,
            "public_key": public_key,
            "signature": signature,
            "iterations": iterations,
            "ext_state": ext_state,
        }
        vectors.append(vector)

        if print_to_stdout:
            print(
                "".join(
                    (
                        f"{seed.hex()},{rp_id},{nonce.hex()},{mac.hex()},{credential_id.hex()},",
                        f"{secret_scalar},{public_key.hex()},{signature.hex()},{iterations}",
                    )
                )
            )

    # have test cases to cover the 1 in 4 billion case
    assert 1 < max_iterations  # <= 2

    # have test cases to cover the shortlist
    _ = select_shortlist(vectors)

    if return_vectors:
        return vectors
