"""
Encryption module.

This module implements a custom stream cipher.
"""

# LCG parameters
A = 1103515245
C = 12345
M = 2**31
A_inv = pow(A, -1, M)

def next_state(state):
    """Generate the next PRNG state."""
    return (A * state + C) % M

def prev_state(state):
    return ((state-C) * A_inv) % M


def generate_keystream(seed, length):
    """Generate a pseudorandom keystream."""
    state = seed
    keystream = bytearray()

    for _ in range(length):
        state = next_state(state)
        keystream.append((state >> 16) & 0xff)

    return bytes(keystream)

def get_canditate_seeds(key, length):
    # 7 bits high, 8 k0, 16 bits low
    k0 = key[0]
    candidates = []

    for high in range(2**7):
        for low in range(2**16):
            state = (high << 24) | (k0 << 16) | low
            current_state = state
            valid = True

            for expected in key[1:]:
                current_state = next_state(current_state)
                output = ((current_state >> 16) & 0xff)
                if output != expected:
                    valid = False
                    break

            if valid:
                candidates.append(prev_state(state))

    return candidates


def encrypt(plaintext, seed):
    """Encrypt plaintext using XOR."""
    keystream = generate_keystream(seed, len(plaintext))
    return bytes(
        p ^ k for p, k in zip(plaintext, keystream)
    )


def decrypt(ciphertext, seed):
    """Decrypt ciphertext using XOR."""
    return encrypt(ciphertext, seed)

def get_keystream():
    known_plain = b"STATUS: SERVER ONLINE"
    known_cipher = bytes.fromhex("22135cc0b9daa9e717f98a998e6ee5e92655e1a88f")
    return bytes(
        p ^ k for p, k in zip(known_plain, known_cipher)
    )

# print(get_keystream().hex())
#
# key = b"6166706760305910317c3637246b45787f7b2f777d"
secret = bytes.fromhex("12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b01d833d628a941b82fb65176b4ed3c3f64")
key = get_keystream()
plain = bytes(
    p ^ k for p, k in zip(secret, key)
)

print(plain.decode(encoding="utf-8"))

canditates = get_canditate_seeds(key, len(secret))

for x in canditates:
    print(decrypt(secret, x).decode(encoding="utf-8"))

# plain = bytes(
#     p ^ k for p, k in zip(secret, key)
# )
#
# print(plain.decode(encoding="utf-8"))
