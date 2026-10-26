import secrets
import base64

k1_small = secrets.randbelow(2**20)
k2_small = secrets.randbelow(2**20)

K1 = k1_small.to_bytes(3, "big") + b"\x00"*13
K2 = k2_small.to_bytes(3, "big") + b"\x00"*13

with open("enc.bmp", "rb") as f:
    enc = f.read()

C = enc[54:70]
P = b"\x00\x00\xff\x00\x00\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\xff"

cipher = bytes.fromhex("df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe738244027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84ffa6745294c224068e1cffd9e8c9e294")

while True:
    k1_small = secrets.randbelow(2**20)
    k2_small = secrets.randbelow(2**20)

    K1 = k1_small.to_bytes(3, "big") + b"\x00"*13
    K2 = k2_small.to_bytes(3, "big") + b"\x00"*13

    plain = bytes(
        p ^ k for p, k in zip(cipher, K1)
    )
    plain = bytes(
        p ^ k for p, k in zip(cipher, K2)
    )
    plain = base64.b64decode(plain)
    if plain.startswith("cns"):
        break
    print(plain)
