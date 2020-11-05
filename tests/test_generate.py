import pytest

import seedweed


def test_seed_constructor():
    from seedweed import assert_32_bytes as assert_valid_seed

    with pytest.raises(AssertionError):
        assert_valid_seed(bytes([0] * 31))
    with pytest.raises(AssertionError):
        assert_valid_seed(bytes([0] * 33))
    with pytest.raises(AssertionError):
        assert_valid_seed([0] * 31)
    with pytest.raises(AssertionError):
        assert_valid_seed("0" * 32)


def test_zero_seed_zero_nonce():
    zero_seed = bytes([0] * 32)
    zero_mac = bytes([0] * 32)

    scalar, point, keypair, iterations = seedweed.keypair_from_seed_mac(
        zero_seed, zero_mac
    )

    assert iterations == 1, iterations
    assert (
        scalar
        == 19437864054269200754977681106621014646072784646180000699501739860764553555251
    )


def test_multi_iteration():
    seed = bytes.fromhex(
        "dd2ca3b88f9491c042fcc04c5e732e9f6fd9c0eb6f3b99cddd4ae96d661ada2c"
    )
    assert seedweed.H(b"seedweed") == seed
    nonce = bytes.fromhex(
        "8b911917c0b74f77e6fb819d6a8034a94f0fca487cacb41e89235c5c5220947b"
    )
    rp_id = "solokeys.com"
    rp_id_hash = seedweed.H(rp_id.encode())
    mac = seedweed.HMAC(seed, rp_id_hash + bytes([1]) + nonce)
    iterations = seedweed.keypair_from_seed_mac(seed, mac)[-1]

    assert iterations == 2


def test_testvector_coverage():
    # this calls `select_shortlist`, which ensures various cases are covered
    _ = seedweed.vectors.generate(print_to_stdout=False, return_vectors=False)
