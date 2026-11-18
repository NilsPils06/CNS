import json
from Crypto.Util.number import long_to_bytes, bytes_to_long

with open("ElGamal_challenge.json", "r") as f:
    data = json.load(f)
    p = data['p'] # q
    g = data['g'] # a
    y = data['y'] # Ya
    plain_known = data['known_plaintext']
    cipher_known = data['cipher_known']
    cipher_flag = data['cipher_flag']

    # K = (C1)^Xa mod q
    # M = (C2 * K^-1) mod q
    # Xa = dlog_a,q(Ya)
    # M2 = (C2,1)^-1 C2,2 M1 mod q
    # C2,1 = (K * M1) mod q
    # C2,2 = (K * M2) mod q
    # C1 = a^k mod q,
    # C2 = a^(k+d) mod q
    m_known = bytes_to_long(data["known_plaintext"].encode())
    c1_known, c2_known = data["cipher_known"]
    c1_flag, c2_flag = data["cipher_flag"]

    # 2. Shared secret van het bekende bericht: s_known = c2_known / m_known
    s_known = c2_known * pow(m_known, -1, p) % p

    # 3. Zoek d zodat c1_flag = c1_known * g^d  (dus k_flag = k_known + d)
    d = None
    for i in range(-1000, 1001):
        if c1_known * pow(g, i, p) % p == c1_flag:
            d = i
            break
    print("d =", d)

    # 4. Shared secret van de flag: s_flag = s_known * y^d
    s_flag = s_known * pow(y, d, p) % p

    # 5. Flag ontsleutelen: m_flag = c2_flag / s_flag
    m_flag = c2_flag * pow(s_flag, -1, p) % p

    # 6. Getal omzetten naar tekst
    flag = long_to_bytes(m_flag)
    print("flag =", flag.decode())
