from Crypto.Cipher import AES
from Crypto.Util import Counter

def encrypt(key, nonce, msg):
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(msg)

def decrypt():
    known_plain = b"According to all known laws of aviation, there is no way a bee should be able to fly."
    with open("ciphertext_known.hex", "rb") as f:
        known_cipher = bytes.fromhex(f.read().strip())

    key = bytes(
        p ^ k for p, k in zip(known_plain, known_cipher)
    )

    with open("ciphertext_flag.hex", "rb") as f:
        cipher = bytes.fromhex(f.read().strip())

    plain = bytes(
        p ^ k for p, k in zip(cipher, key)
    )

    print(plain.decode())

decrypt()
