import pytest
import seedweed

def test_seed_constructor():
    from seedweed import assert_32_bytes as assert_valid_seed

    with pytest.raises(AssertionError):
        assert_valid_seed(bytes([0]*31))
    with pytest.raises(AssertionError):
        assert_valid_seed(bytes([0]*33))
    with pytest.raises(AssertionError):
        assert_valid_seed([0]*31)
    with pytest.raises(AssertionError):
        assert_valid_seed("0"*32)

def test_zero_seed_zero_nonce():
    zero_seed =  bytes([0]*32)
    zero_nonce =  bytes([0]*32)

    scalar, point, keypair, iterations = seedweed.keypair_from_seed_nonce(zero_seed, zero_nonce)

    assert iterations == 1, iterations
    assert scalar == 19437864054269200754977681106621014646072784646180000699501739860764553555251



