import hashlib, json

with open("dsa1_challenge.json", "r") as f:
    data = json.load(f)
    p = data['p']
    q = data['q']
    g = data['g']
    y = data['y']

    signature1 = data['signatures'][0]
    signature2 = data['signatures'][1]

    m1 = signature1['message'].encode()
    r1 = signature1['r']
    s1 = signature1['s']
    m2 = signature2['message'].encode()
    r2 = signature2['r']
    s2 = signature2['s']
    enc_flag = bytes.fromhex(data['encrypted_flag'])

    # H(m) = int(sha256(m)) mod q
    def H(m: bytes) -> int:
        return int.from_bytes(hashlib.sha256(m).digest(), "big") % q

    h1 = H(m1)
    h2 = H(m2)

    k = ((h1 - h2) * pow(s1 - s2, -1, q)) % q

    x = ((s1 * k - h1) * pow(r1, -1, q)) % q

    keystream = b""
    counter = 0
    while len(keystream) < len(enc_flag):
        keystream += hashlib.sha256(f"{x}:{counter}".encode()).digest()
        counter += 1

    flag = bytes(a ^ b for a, b in zip(enc_flag, keystream))
    print(flag.decode())
