seed = bytes.fromhex("59ece2f2bcd6512eea7a6bd1694cf1e73552fbf314e219b06f3e2f864f0d99ed")
assert len(seed) == 32
unique_id = bytes.fromhex("4eed5a99990c4cc9d6065556599383495b316262095b7bb65d37c23ec53e7712")
assert len(unique_id) == 32

def HMAC(key, msg):
    import hashlib
    import hmac
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(msg)
    return mac.digest()

msg = bytes([1]) + unique_id
mac = HMAC(seed, msg)
secret_key = HMAC(seed, mac)

import ecdsa
n = int.from_bytes(secret_key, "little")
assert n >= ecdsa.NIST256p.order
print("found a weirdo!")
print(n)
print(ecdsa.NIST256p.order)
print(n - ecdsa.NIST256p.order)
