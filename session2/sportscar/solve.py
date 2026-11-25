import json
from Crypto.Util.number import long_to_bytes
import math

# Convergents of num/den as fractions
def convergents(num, den):
    # The Euclidean algorithm gives the denominators, then compute convergents
    ni, di = (0, 1), (1, 0)
    while den != 0:
        div = num // den
        num, den = den, num % den
        ni = (ni[1], div * ni[1] + ni[0])
        di = (di[1], div * di[1] + di[0])
        yield (ni[1], di[1])


# Factorizes N when successful
def wiener(N, e):
    for k_guess, d_guess in convergents(e, N):
        if k_guess == 0:
            continue
        phi_guess = (e * d_guess - 1) // k_guess
        # Solve the quadratic
        coeff = N - phi_guess + 1
        disc = coeff * coeff - 4 * N
        if coeff <= 0 or coeff >= N + 1 or disc < 0:
            continue
        root_disc = math.isqrt(disc)
        if root_disc * root_disc != disc:
            continue
        return ((coeff + root_disc) // 2, (coeff - root_disc) // 2)
    return None

with open("challenge.json", "r") as f:
    data = json.load(f)

    n = data['n']
    e = data['e']
    c = data['c']

    w = wiener(n, e)
    if w is not None:
        p = w[0]
        q = w[1]
        d = pow(e, -1, ((p-1)*(q-1)))
        m = long_to_bytes(pow(c,d,n))
        print(m)
