import secrets, json
from Crypto.Cipher import Salsa20

def encrypt_transaction(transaction):
    """Encrypt a transaction using Salsa20."""
    nonce = secrets.token_bytes(8)

    cipher = Salsa20.new(key=KEY, nonce=nonce)

    plaintext = json.dumps(
        transaction,
        separators=(",", ":")
    ).encode()
    print(plaintext)

    ciphertext = cipher.encrypt(plaintext)

    # Transmit nonce alongside ciphertext
    return nonce + ciphertext

def decrypt_transaction(transaction):
    plaintext = b"{\"from\":\"alice\",\"to\":\"bob\",\"amount\": \"000010\"}"
    newtext = b"{\"from\":\"alice\",\"to\":\"bob\",\"amount\": \"001000\"}"
    nonce = bytearray()
    for i in range(8):
        nonce.append(transaction[0])
        transaction.pop(0)

    key = bytearray(
        p ^ k ^ s for p, k, s in zip(transaction, newtext, plaintext)
    )

    for i in range(8):
        key.insert(i, nonce[i])

    print(key.hex())

decrypt_transaction(bytearray.fromhex("30e9163847c8faf221e0c298cb503bf20636813d3f7d3419cc8c118e5c86633c4c92c8da16887a85abd00e11ecd35e4f2a0af3d560"))
