from Crypto.Cipher import AES

# 1. Lees enc.bmp in
with open("enc.bmp", "rb") as f:
    enc = f.read()

# Known-plaintext:
# Het eerste blok na de 54-byte BMP header (bytes 54:70) bevat de vaste RGB(A) bitmaskers van BITMAPV5HEADER:
P = b"\x00\x00\xff\x00\x00\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\xff"
C = enc[54:70]

cipher = bytes.fromhex(
    "df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe73824"
    "4027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84"
    "ffa6745294c224068e1cffd9e8c9e294"
)

# 2. Meet-in-the-Middle aanval:
# Double AES: C = E_K2(E_K1(P))  <=>  E_K1(P) = D_K2(C)
# In plaats van 2^(20+20) = 2^40 pogingen, doen we 2^20 + 2^20 = 2 * 10^6 operaties.

print("Fase 1: Hash-tabel opbouwen voor alle 2^20 mogelijke K1 waarden...")
table = {}
for k1 in range(2**20):
    K1 = k1.to_bytes(3, "big") + b"\x00" * 13
    mid = AES.new(K1, AES.MODE_ECB).encrypt(P)
    table[mid] = k1

print("Fase 2: Zoeken naar matchende K2...")
found_k1 = None
found_k2 = None
for k2 in range(2**20):
    K2 = k2.to_bytes(3, "big") + b"\x00" * 13
    mid = AES.new(K2, AES.MODE_ECB).decrypt(C)
    if mid in table:
        found_k1 = table[mid]
        found_k2 = k2
        print(f"Match gevonden! K1: {found_k1}, K2: {found_k2}")
        break

# 3. Ontcijferen van de promo-code / vlag
if found_k1 is not None and found_k2 is not None:
    K1 = found_k1.to_bytes(3, "big") + b"\x00" * 13
    K2 = found_k2.to_bytes(3, "big") + b"\x00" * 13

    aes1 = AES.new(K1, AES.MODE_ECB)
    aes2 = AES.new(K2, AES.MODE_ECB)

    # Volgorde van decryptie: eerst K2 ongedaan maken, daarna K1
    plain = aes1.decrypt(aes2.decrypt(cipher))
    print("\nOntcijferde promo-code:")
    print(plain.strip().decode("utf-8", errors="replace"))

    # Optioneel: enc.bmp ontcijferen
    header = enc[:54]
    body = enc[54:]
    decrypted_bmp = header + aes1.decrypt(aes2.decrypt(body))
    with open("dec.bmp", "wb") as f:
        f.write(decrypted_bmp)
    print("\nOntcijferde afbeelding opgeslagen als dec.bmp")
