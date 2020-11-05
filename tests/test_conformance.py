"""Test that our conformance tests actually test what we want to test."""

import ecdsa
import pytest

import seedweed

sample_conformance_inputs = {
    0: {
        "authnr_signature": b"c\x85\xa5n\x9a\xc4\xe2\x80\xde6\xcb&.\xa7U_c\\\x8eK;\xdbe\x8b\xdc7M3\xf7B\xa3$\x1b\x8a\x8e\xb6\x0b\x98s\xd6\xfd\x8c+\xd4{P\x93U\xd3\x82k\xb9\xac\xb3\xa4\xee\x1e\xe9\x02\xfa\xb2G\xe1=",  # noqa: E501
        "signed_data": b"\xc0\xfc\r\x93\x12h\xfcw\x0b`g\xa58\x99\x8c\xdb\xb6\x91\x8b~\xdd\x97e\xa6\xfd.\x9as\xc3\x87\xf1\xae\x01\x00\x00\x00\x00123456789abcdef0123456789abcdef0",  # noqa: E501
    },
    1: {
        "authnr_signature": b"\x8bv\x8a\xd3\xe1S&0j\xc5,\xf1j\xc7\xd2\xd9\xb4H\xe8\xa6\x97\xed8\xeep\xca\xa4&Bx\x1c.\xbf\xbe\xda\x8a\x0e\xd4\xd0\xc9\x98\xcd\xa8\xc5\x0b\\\x88\xea\xbc\xeeM^}\x86QyD%\xa6\x8d\xa7\x91<+",  # noqa: E501
        "signed_data": b"\x95\x9d=\xd2\x98\xaf\x1b\xb0\xd0{\xdd\xbd\xb3-\xdd\x0b\xaf\xe7\x03\x8b\xd0[\x02\xe0\x1b\x82\xbf\x0e\x0e\x0e9\xc5\x01\x00\x00\x00\x00123456789abcdef0123456789abcdef0",  # noqa: E501
    },
    2: {
        "authnr_signature": b'\xea\xabH\x0c\x88\xd0\x01-N\xce[\xce\xbd\xea\xe4)\xc3\xb4\xd1*\x03\xf5\xce\xb4\xb2\xba\x98\x81U\x8bX\x18\xd2h\xf6\x9e\x1f\x98\xdc\xc5\xbb\x90F\xe4D<\xa2\xe4\xf7AZP-8\x96\xc8\xd7\xcb"\x99\xe7\xddZ\x1e',  # noqa: E501
        "signed_data": b"5\x97\x92\xf9\xea\xee\x1ay\x99 \xcf\x86\xf04\xe8\xc6f:\x10\xfb\x80`\xad\xd3\xa4-\xf1\xd7\xd4\xf4\x88\xf2\x01\x00\x00\x00\x00123456789abcdef0123456789abcdef0",  # noqa: E501
    },
    36: {
        # "authnr_signature": b'\xac\x19D\xd1\\\xf9j\xd8\xc9\xa0\xfa\xda!|3\x89\xa3\xc2\xf7\xe4\x95\x9a\xf7\x01>\x11\xac\xe6\x197\x86\x7f\x90\xef\xa1\x1ak\xf3\xa4\xc9.\xb5H\x16\t\xd6"\xc81\xe8\xe9\xca\x0c\x8c\xd7U-{<NR\x03\xadz',  # noqa: E501
        "authnr_signature": b"8b\x17\t\xcb\xd8z^\xfe\xf0v\xa9\x97\xb6\xca\xca\xfd\xbaBr~\x1f\xcd\xa9SN\xcc\xa4\x08\xcf\x87QV,>I\x05\xc9$\x87\x1dm\xff\x81\xf2\xb80\xcbi\xdcw\xc36\xb0\x96\xee\xc2\x9b\x1f4\x9c?\t>",  # noqa: E501
        "signed_data": b"\xc0\xfc\r\x93\x12h\xfcw\x0b`g\xa58\x99\x8c\xdb\xb6\x91\x8b~\xdd\x97e\xa6\xfd.\x9as\xc3\x87\xf1\xae\x01\x00\x00\x00\x00123456789abcdef0123456789abcdef0",  # noqa: E501
    },
}


@pytest.fixture
def vectors():
    return seedweed.load_test_vectors(shortlist=False)


def test_make_credential_conformance():
    testvector = {
        "seed": b"\xdd,\xa3\xb8\x8f\x94\x91\xc0B\xfc\xc0L^s.\x9fo\xd9\xc0\xebo;\x99\xcd\xddJ\xe9mf\x1a\xda,",  # noqa: E501
        "rp_id": "example.com",
    }
    authnr_credential_id = b"\x01\xb1\xd93uA\xfc\x03\xccG\x86t=eg\xe9\xea\x8b]\xa75\x9a;\xe4h\xd9`\x94\xab/\x8d\x8e4sunny side up\xe8\xb3\xd0K*vz:}g\x0e\x0eS\xa7\xaf.\xca\x95mA\xcf\xd8\x8dlN\x830\xa5\x9e\x91\xc1%"  # noqa: E501
    # authnr_credential_public_key = bytes.fromhex("331717b78ab7589f470063179eb5802ba79576defcc5ce221b79746dd9f7428854a5d9c75b62e85735f24371aac26da78cd0fc2a468110b40b48ca859fec8b65")  # noqa: E501
    authnr_credential_public_key = bytes.fromhex(
        "072b9f682bd8ca8d81f071c0050178137f846e3f83e920cff4d9ee09b2f69fecaae5d93152464d32c33e18cf108249cf3fac0edb805f6b59459d1d7a3f1a2692"  # noqa: E501
    )

    seedweed.conformance.verify_make_credential(
        testvector, authnr_credential_id, authnr_credential_public_key
    )


def test_get_assertion_conformance(vectors):
    for case, inputs in sample_conformance_inputs.items():
        seedweed.conformance.verify_get_assertion(
            vectors[case],
            inputs["authnr_signature"],
            inputs["signed_data"],
        )


def test_non_conformance(vectors):
    # This is an example of a signature where the authenticator did not
    # generate the private key correctly, and hence generates an incorrect signature.
    bad_authnr_signature = b'\xac\x19D\xd1\\\xf9j\xd8\xc9\xa0\xfa\xda!|3\x89\xa3\xc2\xf7\xe4\x95\x9a\xf7\x01>\x11\xac\xe6\x197\x86\x7f\x90\xef\xa1\x1ak\xf3\xa4\xc9.\xb5H\x16\t\xd6"\xc81\xe8\xe9\xca\x0c\x8c\xd7U-{<NR\x03\xadz'  # noqa: E501

    with pytest.raises(ecdsa.keys.BadSignatureError):
        seedweed.conformance.verify_get_assertion(
            vectors[36],
            bad_authnr_signature,
            sample_conformance_inputs[36]["signed_data"],
        )


def test_incorrectness(vectors):
    vectors = seedweed.load_test_vectors()

    vector = vectors[36]
    seed, mac = vector["seed"], vector["mac"]
    mac = vector["mac"]
    print(seed)
    print(mac)
    incorrect_keypair = _incorrect_keypair_from_seed_mac(seed, mac)
    incorrect_pubkey = incorrect_keypair.verifying_key._raw_encode()
    print(vector.keys())
    assert vector["public_key"] != incorrect_pubkey, vector.keys()


def _incorrect_keypair_from_seed_mac(seed: bytes, mac: bytes) -> ecdsa.SigningKey:
    import seedweed.reference as reference

    reference.assert_32_bytes(seed)
    reference.assert_32_bytes(mac)

    P256 = reference.ecdsa.NIST256p

    candidate_bytes = reference.HMAC(seed, mac)
    candidate_scalar = int.from_bytes(candidate_bytes, "little")
    secret_scalar = candidate_scalar % reference.P256.order
    # public_point = secret_scalar * reference.P256.generator
    keypair = reference.ecdsa.SigningKey.from_secret_exponent(secret_scalar, P256)
    # iterations = 1

    # return secret_scalar, public_point, keypair, iterations
    return keypair
