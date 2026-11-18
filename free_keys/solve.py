import json
from Crypto.Util.number import long_to_bytes

def gcdExtended(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = gcdExtended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

with open("challenge.json", "r") as f:
    data = json.load(f)

    n = data['n']
    e1 = data['e1']
    e2 = data['e2']
    c1 = data['c1']
    c2 = data['c2']

    # M = c1^a * c2^b mod n
    # ae1 + be2 = 1
    gcd, a, b = gcdExtended(e1, e2)
    if gcd == 1:
       M = (pow(c1, a, n) * pow(c2, b, n)) % n
       M = long_to_bytes(M)
       print(M)
