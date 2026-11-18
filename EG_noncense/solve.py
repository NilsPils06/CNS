import json

from sympy import discrete_log
from Crypto.Util.number import long_to_bytes, bytes_to_long

with open("challenge.json", "r") as f:
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
    m_known = bytes_to_long(plain_known.encode())
    M = (pow(cipher_known[1], -1, p) * cipher_flag[1] * m_known) % p
    print(long_to_bytes(M))
