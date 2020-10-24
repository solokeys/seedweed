""" Find setups where the P256 key construction takes more than one interation. """

import hashlib
import hmac
import random
import secrets

import ecdsa
import seedweed

P256 = ecdsa.NIST256p

def random_bytes(length):
    return random.getrandbits(8*length).to_bytes(n, 'little')


def HMAC(key: bytes, data: bytes) -> bytes:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(data)
    return mac.digest()

# seed = random_bytes(32)
seed = seedweed.H(b"seedweed")
print(f"seed = {seed.hex()}")

random.seed(2020)
search_seed = secrets.token_bytes(32)
# search_seed = bytes.fromhex("252dbf25c582dfa486f89f692d3c742152e81f35d7240668f2b026a02bd4ae83")
print(f"search seed = {search_seed.hex()}")
rng = random.Random(search_seed)

order = P256.order
found = 0

rp_id = "solokeys.com".encode()
rp_id_hash = seedweed.H(rp_id)
with open(f"{search_seed.hex()}.log", "w") as fh:
    # for i in range(2**32):
    # for i in range(1000000000):
    for i in range(2**64):
        # mac = int(i).to_bytes(32, "big")
        unique_id = rng.getrandbits(256).to_bytes(32, 'big')
        mac = HMAC(seed, rp_id_hash + bytes([1]) + unique_id)
        candidate = int.from_bytes(HMAC(seed, mac), "little")

        if candidate >= order:
            found += 1
            entry = f"i = {i}: HMAC({seed.hex()},HMAC(seed, H(b'example.com') + [1] + {unique_id.hex()})) = {candidate}"
            print(entry)
            fh.write(entry + "\n")
            fh.flush()

            if True:
                fh.close()
                import sys
                sys.exit(0)

        if i % int(1e6) == 0:
            print(f"found {found} after {i}")


# 275edb1c190bd62fc400df5045190cfc647b0956a390685389d7b404a86a3073.log
# HMAC(
#   59ece2f2bcd6512eea7a6bd1694cf1e73552fbf314e219b06f3e2f864f0d99ed,
#   fd7fc7d2b1b49c7cba47dd3e7a5f3cb991bf0b62388e720bd9be272163a6a725,
# ) = 115792089226597647821555558773243515956592285713205569838850865706012713790799

