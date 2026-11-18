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
    m_known = bytes_to_long(plain_known.encode())
    K = (cipher_known[1] * pow(m_known, -1, p)) % p
    M = (cipher_flag[1] * pow(K, -1, p)) % p
    print(long_to_bytes(M).decode())
