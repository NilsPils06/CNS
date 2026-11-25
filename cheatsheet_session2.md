# CNS Hacking Session 2 — Cheatsheet
**Vak:** Computer and Network Security (UAntwerpen)  
**Scope:** Part 4 (Number Theory, Asymmetric Encryption: RSA, ElGamal, Digital Signatures/DSA/RSA-PSS) & Part 5 (Mutual Trust: Key Distribution, Diffie-Hellman, Public Key Directories/Certificates/X.509, KDC, Kerberos) + alle oefeningen uit `session2/`.

---

## 1. Snelle Triage: "Herken de Aanval"

Gebruik deze tabel zodra je een nieuwe challenge opent (`challenge.json`, `public_keys.txt`, of een HTTP/TCP API):

| Wat zie je in de challenge? | Waarschijnlijke aanval | Sectie | Oefening in `session2/` |
| :--- | :--- | :---: | :--- |
| **RSA** met kleine `n` (< ~100 bits / < 30 cijfers) | Factorisatie (`sympy.factorint` / `totient`) | [3.1](#31-kleine-n--zwakke-priemgetallen) | `SiftingSand` |
| **RSA** met `e = 3` en `c1 == c2 == c3` (of 1 ciphertext met kleine `M`) | Directe $e$-de wortel ($M^e < n$) | [3.2](#32-kleine-e-en-kleine-m-of-håstads-broadcast-attack) | `TheGroupChat` |
| **RSA** met `e = 3` (klein), **3 verschillende `n_i`**, zelfde bericht `M` | **Håstad's Broadcast Attack** (CRT + $e$-de wortel) | [3.2](#32-kleine-e-en-kleine-m-of-håstads-broadcast-attack) | `TheBetterGroupChat` |
| **RSA** met **dezelfde `n`**, 2 verschillende `e1, e2` ($\gcd=1$), zelfde `M` | **Common Modulus Attack** (Extended GCD) | [3.3](#33-common-modulus-attack-zelfde-n-verschillende-e) | `FreeKeys` |
| **RSA** met **enorm grote `e`** ($e \approx n$, bijna evenveel cijfers) | **Wiener's Attack** (kleine $d < \frac{1}{3}n^{1/4}$) | [3.4](#34-wieners-attack-kleine-d--enorm-grote-e) | `SportsCarDesire` |
| **RSA** met meerdere publieke sleutels `n1, n2, ...` | **Common Factor Attack** ($\gcd(n_1, n_2) > 1$) | [3.1](#31-kleine-n--zwakke-priemgetallen) | *(extra uit slides)* |
| **RSA** met $p \approx q$ of $p-1$ smooth (veel kleine factoren) | **Fermat Factorization** / **Pollard's $p-1$** | [3.1](#31-kleine-n--zwakke-priemgetallen) | *(extra uit slides)* |
| **RSA** decryptie-/sign-oracle (die target `c` weigert) | **Chosen Ciphertext Attack (CCA)** / Blinding ($C' = C \cdot 2^e \bmod n$) | [3.5](#35-chosen-ciphertext-attack-cca--malleability) | *(slides p. 55–56)* |
| **ElGamal** met **dezelfde `c1`** voor bekend bericht & flag | **ElGamal Nonce Reuse** ($M_2 = C_{2,1}^{-1} C_{2,2} M_1 \bmod p$) | [4.1](#41-elgamal-nonce-reuse-c_11--c_12) | `AsymmetricNonsense` |
| **ElGamal** met verschillende `c1`, maar bekende plaintext | **Related Nonce** ($k_2 = k_1 + \Delta \Rightarrow c_{1,2} = c_{1,1} g^\Delta \bmod p$) | [4.2](#42-elgamal-related--voorspelbare-nonce-k_2--k_1--delta) | `FreshEveryTime` |
| **ElGamal / DH** met kleine `p` of $p-1$ smooth | **Discrete Log** (`sympy.discrete_log` / Pohlig-Hellman) | [4.3](#43-zwakke-p-discrete-log--pohlig-hellman) | *(slides p. 68)* |
| **DSA** met 2 signatures met **dezelfde `r`** (`r1 == r2`) | **DSA Nonce Reuse** $\rightarrow$ herstel $k$ en private key $x$ | [5.1](#51-dsa-nonce-reuse-r_1--r_2) | `DoubleEntry` |
| **DSA** met 2 signatures met gerelateerde nonce ($k_2 = k_1 + \Delta$) | **DSA Related Nonce** $\rightarrow$ brute-force $\Delta$, check $g^x \equiv y$ | [5.2](#52-dsa-related-nonce-of-bekende-k) | *(uitbreiding)* |
| **Web/API** met `/directory`, public key registratie of DH zonder auth | **Key Spoofing / MitM** (eigen sleutelpaar registreren) | [6.1](#61-public-key-directory-spoofing--mitm) | `PhoneBook` |
| **KDC / Kerberos / X.509** protocol-challenge | **Replay attack**, ontbrekende validatie, PCBC/AS-REP | [6.2](#62-kdc-x509--kerberos-aanvallen--concepten) | *(Part 5 slides)* |

---

## 2. Python & Getaltheorie Toolbox

Beschikbaar in je Nix devshell (`flake.nix`): `pycryptodome`, `cryptography`, `sympy`, `requests`, Python 3.14.

```python
import math, json, hashlib, requests
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, GCD
from sympy import factorint, totient, discrete_log, integer_nthroot, isprime
from sympy.ntheory.modular import crt

# Basis conversies
m_int   = bytes_to_long(b"plaintext")
m_bytes = long_to_bytes(m_int)
# Bij fixed-size blokken (zoals SiftingSand):
block   = m_int.to_bytes(block_size, byteorder="big")

# Modulaire rekenkunde (ingebouwd in Python 3.8+!)
c     = pow(m, e, n)        # m^e mod n  (Square-and-Multiply)
inv_a = pow(a, -1, n)       # a^(-1) mod n (werkt ook met pow(a, -k, n)!)
g     = math.gcd(a, b)      # ggd(a, b)
root  = math.isqrt(n)       # exacte floor(sqrt(n)) zonder float-fouten!
r, ok = integer_nthroot(C, e)  # exacte e-de wortel; ok=True als exact

# Extended Euclidean Algorithm: vindt (g, x, y) zodat a*x + b*y = g
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    return g, y1 - (b // a) * x1, x1
```

### Belangrijke stellingen (Part 4 Homework)
- **Fermat's Little Theorem:** Als $p$ priem en $p \nmid a$: $a^{p-1} \equiv 1 \pmod p$ (algemeen: $a^p \equiv a \pmod p$).
- **Euler's Theorem:** Als $\gcd(a, n) = 1$: $a^{\phi(n)} \equiv 1 \pmod n$, waarbij $\phi(pq) = (p-1)(q-1)$ voor $p, q$ priem.
- **Chinese Remainder Theorem (CRT):** Voor paarsgewijs relatief prieme $m_1, \dots, m_k$ met $M = \prod m_i$:
  $$A \equiv \sum_{i=1}^k a_i M_i (M_i^{-1} \bmod m_i) \pmod M, \quad M_i = M / m_i$$
  In Python: `A, M = crt([m1, m2, m3], [a1, a2, a3])`
- **Primitieve wortel:** $a$ is primitieve wortel van priem $p$ als kleinste $m > 0$ met $a^m \equiv 1 \pmod p$ gelijk is aan $\phi(p) = p-1$.
- **Discrete logaritme:** $\operatorname{dlog}_{a,p}(b) = i \iff b \equiv a^i \pmod p$.
- **Miller-Rabin:** Probabilistische priemtest; false positive rate $(1/4)^t$ na $t$ iteraties.

---

## 3. RSA — Formules & Aanvallen

### Basisformules
- $n = p \cdot q$, $\quad \phi(n) = (p-1)(q-1)$
- Public key: $(e, n)$ met $\gcd(e, \phi(n)) = 1$ (vaak $e = 65537 = 2^{16}+1$, weinig 1-bits $\Rightarrow$ snelle encryptie)
- Private key: $(d, n)$ met $d \equiv e^{-1} \pmod{\phi(n)}$
- Encryptie: $C = M^e \bmod n \quad$ | $\quad$ Decryptie: $M = C^d \bmod n$
- Max blokgrootte: $M < n$, praktisch $i$ bits met $2^i \le n \le 2^{i+1}$ ($\lfloor \log_2 n \rfloor$ bits).
- **RSA-CRT versnelling (~4x sneller):**
  $$V_p = C^{d \bmod (p-1)} \bmod p, \quad V_q = C^{d \bmod (q-1)} \bmod q$$
  $$X_p = q(q^{-1} \bmod p), \quad X_q = p(p^{-1} \bmod q), \quad M = (V_p X_p + V_q X_q) \bmod n$$

---

### 3.1 Kleine $n$ & Zwakke priemgetallen

1. **Kleine $n$** (`SiftingSand`): gebruik `sympy.totient(n)` of `sympy.factorint(n)`.
```python
from sympy import totient, factorint
# Direct via totient (of factorint(n)):
d = pow(e, -1, int(totient(n)))
# Per blok:
m = pow(c, d, n)
```

2. **Common Factor Attack** (meerdere moduli $n_i$ delen een priemfactor $p$):
```python
import math
p = math.gcd(n1, n2)
if 1 < p < n1:
    q1 = n1 // p
    d1 = pow(e, -1, (p - 1) * (q1 - 1))
```

3. **Fermat Factorization** ($p$ en $q$ liggen dicht bij elkaar, $|p - q|$ klein):
```python
import math
def fermat_factor(n):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    while True:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
```

4. **Pollard's $p-1$** ($p-1$ heeft alleen kleine priemfactoren, i.t.t. slide 53):
```python
import math
def pollard_pm1(n, B=100000):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        if j % 100 == 0:
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g, n // g
    g = math.gcd(a - 1, n)
    return (g, n // g) if 1 < g < n else None
```

---

### 3.2 Kleine $e$ en kleine $M$, of Håstad's Broadcast Attack

- **Geval A: $M^e < n$** (`TheGroupChat` — herkenbaar aan kleine $e$ zoals $e=3$, of $c_1 == c_2 == c_3$):
  Er gebeurt geen modulo-reductie, dus $C = M^e$ exact over $\mathbb{Z}$!
  ```python
  from sympy import integer_nthroot
  from Crypto.Util.number import long_to_bytes

  m, exact = integer_nthroot(c, e)
  print(long_to_bytes(m))
  ```

- **Geval B: Håstad's Broadcast Attack** (`TheBetterGroupChat` — zelfde bericht $M$ zonder padding versleuteld naar $e$ ontvangers met verschillende $n_1, \dots, n_e$):
  Omdat $M < n_i$, geldt $M^e < n_1 n_2 \cdots n_e$. Met CRT vind je $C = M^e \bmod (n_1 \cdots n_e) = M^e$.
  ```python
  from sympy.ntheory.modular import crt
  from sympy import integer_nthroot
  from Crypto.Util.number import long_to_bytes

  C, N = crt([n1, n2, n3], [c1, c2, c3])  # voor e=3 (algemeen: lijst van e moduli/ciphertexts)
  m, exact = integer_nthroot(int(C), 3)
  assert exact
  print(long_to_bytes(m))
  ```
  *Countermeasure (slide 36):* voeg unieke pseudorandom padding toe (zoals OAEP) aan elke encryptie van $M$.

---

### 3.3 Common Modulus Attack (zelfde $n$, verschillende $e$)
(`FreeKeys`) — Zelfde bericht $M$ versleuteld met $(e_1, n)$ en $(e_2, n)$ waarbij $\gcd(e_1, e_2) = 1$.

Wiskunde: zoek $a, b$ met $a e_1 + b e_2 = 1$. Dan:
$$c_1^a \cdot c_2^b \equiv (M^{e_1})^a (M^{e_2})^b = M^{a e_1 + b e_2} = M^1 \equiv M \pmod n$$

```python
from Crypto.Util.number import long_to_bytes

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    return g, y1 - (b // a) * x1, x1

g, a, b = egcd(e1, e2)
# In Python 3.8+ berekent pow(c, negatief, n) automatisch de modulaire inverse!
m = (pow(c1, a, n) * pow(c2, b, n)) % n
# Tip: als g > 1, dan is m eigenlijk M^g mod n -> probeer integer_nthroot(m, g)
print(long_to_bytes(m))
```

---

### 3.4 Wiener's Attack (kleine $d$ / enorm grote $e$)
(`SportsCarDesire` — slide 53: als $e < n$ en $d < \frac{1}{3} n^{1/4}$, dan is $k/d$ een convergent van de kettingbreuk van $e/n$).  
**Herkenning:** `e` is geen 65537 maar bijna even groot als `n`!

```python
import math
from Crypto.Util.number import long_to_bytes

def convergents(num, den):
    ni, di = (0, 1), (1, 0)
    while den != 0:
        q = num // den
        num, den = den, num % den
        ni = (ni[1], q * ni[1] + ni[0])
        di = (di[1], q * di[1] + di[0])
        yield ni[1], di[1]

def wiener(n, e):
    for k, d in convergents(e, n):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1               # p + q
        disc = s * s - 4 * n          # (p - q)^2
        if s <= 0 or disc < 0:
            continue
        r = math.isqrt(disc)
        if r * r == disc:
            p, q = (s + r) // 2, (s - r) // 2
            if p * q == n:
                return p, q, d
    return None

p, q, d = wiener(n, e)
print(long_to_bytes(pow(c, d, n)))
```

---

### 3.5 Chosen Ciphertext Attack (CCA) & Malleability
(Slides p. 55–56) — Textbook RSA is **multiplicatief homomorf**:
$$E(M_1) \cdot E(M_2) \equiv E(M_1 \cdot M_2) \pmod n$$

- **Decryptie-oracle weigert target ciphertext $C$:**
  1. Kies $r = 2$ (of willekeurige $r$ met $\gcd(r, n) = 1$).
  2. Bereken $X = (C \cdot r^e) \bmod n$ en stuur $X$ naar de decryptie-oracle.
  3. Ontvang $Y = X^d \equiv (M \cdot r) \pmod n$.
  4. Bereken $M = (Y \cdot r^{-1}) \bmod n$:
     ```python
     r = 2
     X = (C * pow(r, e, n)) % n
     # Y = oracle_decrypt(X)
     M = (Y * pow(r, -1, n)) % n
     ```
- **Signature-oracle weigert target message $M$:**
  - Factoriseer $M = M_1 \cdot M_2$, vraag signatures $S_1 = M_1^d \bmod n$ en $S_2 = M_2^d \bmod n$ $\Rightarrow S = S_1 \cdot S_2 \bmod n$.
  - Of gebruik blinding: vraag signature voor $M' = M \cdot r^e \bmod n \Rightarrow S' \equiv M^d r \pmod n \Rightarrow S = S' \cdot r^{-1} \bmod n$.
- **Timing attack countermeasure (Blinding, slide 55):**
  $C' = C \cdot r^e \bmod n \to M' = (C')^d \bmod n \to M = M' \cdot r^{-1} \bmod n$.
- **CCA countermeasure (slide 57):** **OAEP** (Optimal Asymmetric Encryption Padding) met random seed en MGF.

---

## 4. ElGamal — Formules & Aanvallen

> **Let op notatieverschil:** Slides gebruiken $(q, \alpha, X_A, Y_A)$; JSON/Python gebruikt meestal $(p, g, x, y)$.

### Basisformules
- Publieke parameters: priem $p$ ($q$), primitieve wortel $g$ ($\alpha$), public key $y = g^x \bmod p$ ($Y_A$).
- Private key: $x$ ($X_A$), met $1 < x < p - 1$.
- **Encryptie** van bericht $M$ met unieke random nonce $k$:
  $$K = y^k \bmod p, \quad C_1 = g^k \bmod p, \quad C_2 = (K \cdot M) \bmod p$$
- **Decryptie** met private key $x$:
  $$K = C_1^x \bmod p, \quad M = (C_2 \cdot K^{-1}) \bmod p$$

```python
# Standaard ElGamal decryptie als je x kent (zie PhoneBook):
K = pow(c1, x, p)
m = (c2 * pow(K, -1, p)) % p
print(long_to_bytes(m))
```

---

### 4.1 ElGamal Nonce Reuse ($C_{1,1} == C_{1,2}$)
(`AsymmetricNonsense` — slide 67) — Zelfde nonce $k$ gebruikt voor bekend bericht $M_1$ en geheim bericht $M_2$:
$$C_{2,1} = K M_1 \bmod p, \quad C_{2,2} = K M_2 \bmod p \implies M_2 = C_{2,1}^{-1} \cdot C_{2,2} \cdot M_1 \bmod p$$

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes

m1 = bytes_to_long(known_plaintext.encode())
c1_1, c2_1 = cipher_known
c1_2, c2_2 = cipher_flag
assert c1_1 == c1_2

m2 = (pow(c2_1, -1, p) * c2_2 * m1) % p
print(long_to_bytes(m2))
```

---

### 4.2 ElGamal Related / Voorspelbare Nonce ($k_2 = k_1 + \Delta$)
(`FreshEveryTime`) — Nonce wordt niet hergebruikt maar bijv. opgehoogd ($k_2 = k_1 + \Delta$):
- Dan is $C_{1,2} = g^{k_1 + \Delta} \equiv C_{1,1} \cdot g^\Delta \pmod p$
- En $K_2 = y^{k_1 + \Delta} \equiv K_1 \cdot y^\Delta \pmod p$, met $K_1 = C_{2,1} \cdot M_1^{-1} \bmod p$

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes

m_known = bytes_to_long(known_plaintext.encode())
c1_k, c2_k = cipher_known
c1_f, c2_f = cipher_flag

K_known = (c2_k * pow(m_known, -1, p)) % p

# Zoek kleine offset d (bijv. -1000..1000) zodat c1_f == c1_k * g^d mod p
d = next(i for i in range(-1000, 1001) if (c1_k * pow(g, i, p)) % p == c1_f)

K_flag = (K_known * pow(y, d, p)) % p
m_flag = (c2_f * pow(K_flag, -1, p)) % p
print(long_to_bytes(m_flag))
```
*Algemenere relatie:* als $k_2 = a \cdot k_1 + b$, dan $C_{1,2} \equiv C_{1,1}^a \cdot g^b \pmod p$ en $K_2 \equiv K_1^a \cdot y^b \pmod p$.

---

### 4.3 Zwakke $p$ (Discrete Log / Pohlig-Hellman) & Malleability
- **Kleine $p$ of smooth $p-1$** (slide 68: veilig vereist $p \ge 300$ cijfers en grote priemfactor in $p-1$):
  ```python
  from sympy import discrete_log
  x = discrete_log(p, y, g)          # herstelt private key x (gebruikt Pohlig-Hellman + BSGS)
  # of herstel k direct uit c1:
  k = discrete_log(p, c1, g)
  K = pow(y, k, p)
  m = (c2 * pow(K, -1, p)) % p
  ```
- **ElGamal Malleability (CCA):** $(C_1, \; C_2 \cdot r \bmod p)$ decrypteert naar $(M \cdot r) \bmod p$.

---

## 5. Digital Signatures (DSA & RSA-PSS)

### DSA Basisformules (slides 74–76)
- Globale publieke parameters: $(p, q, g)$ met $q \mid (p-1)$, $g = h^{(p-1)/q} \bmod p > 1$.
- Private key: $0 < x < q$. Public key: $y = g^x \bmod p$.
- **Signing** met unieke random $k \in (0, q)$:
  $$r = (g^k \bmod p) \bmod q, \qquad s = k^{-1} (H(m) + x \cdot r) \bmod q$$
- **Verificatie** (check eerst $0 < r < q$ en $0 < s < q$!):
  $$w = s^{-1} \bmod q, \quad u_1 = H(m)w \bmod q, \quad u_2 = rw \bmod q, \quad v = (g^{u_1} y^{u_2} \bmod p) \bmod q$$
  Geldig als $v == r$.

---

### 5.1 DSA Nonce Reuse ($r_1 == r_2$)
(`DoubleEntry`) — Dezelfde $k$ gebruikt voor 2 verschillende berichten $m_1, m_2$ (herkenbaar aan $r_1 == r_2$):
$$s_1 - s_2 \equiv k^{-1}(h_1 - h_2) \pmod q \implies k = (h_1 - h_2)(s_1 - s_2)^{-1} \bmod q$$
$$x = (s_1 \cdot k - h_1) \cdot r_1^{-1} \bmod q$$

```python
import hashlib

def H(m: bytes) -> int:
    # Check altijd hoe H(m) in de challenge gedefinieerd is (sha1/sha256, mod q)!
    return int.from_bytes(hashlib.sha256(m).digest(), "big") % q

h1, h2 = H(m1), H(m2)
assert r1 == r2

k = ((h1 - h2) * pow(s1 - s2, -1, q)) % q
x = ((s1 * k - h1) * pow(r1, -1, q)) % q
assert pow(g, x, p) == y  # directe verificatie!
```

---

### 5.2 DSA Related Nonce of Bekende $k$
- **Als $k$ bekend is (of klein genoeg om te brute-forcen via $r = (g^k \bmod p) \bmod q$):**
  $$x = (s \cdot k - H(m)) \cdot r^{-1} \bmod q$$
- **Als $k_2 = k_1 + \Delta$ (bijv. teller $+1$):**
  $$x = \big(s_2 h_1 - s_1 h_2 + s_1 s_2 \Delta\big) \cdot (s_1 r_2 - s_2 r_1)^{-1} \bmod q$$
  ```python
  for delta in range(-1000, 1001):
      num = (s2 * h1 - s1 * h2 + s1 * s2 * delta) % q
      den = (s1 * r2 - s2 * r1) % q
      if den == 0:
          continue
      x = (num * pow(den, -1, q)) % q
      if pow(g, x, p) == y:
          print(f"Gevonden! delta={delta}, x={x}")
          break
  ```
- **Missing $r=0$ / $s=0$ check:** als verificatie niet checkt op $0 < r < q$ en $0 < s < q$, kan soms een triviale forgery gemaakt worden.

---

### 5.3 RSA-PSS Overzicht (slides 77–80)
- **Signing:** $M \to \text{mHash} = H(M)$, kies random `salt`, $M' = \text{padding}_1 \mathbin{\|} \text{mHash} \mathbin{\|} \text{salt}$, $H = H(M')$, $DB = \text{padding}_2 \mathbin{\|} \text{salt}$, $\text{maskedDB} = DB \oplus \text{MGF1}(H)$, $EM = \text{maskedDB} \mathbin{\|} H \mathbin{\|} \text{0xbc}$, signature $s = EM^d \bmod n$.
- **Verificatie:** $EM = s^e \bmod n$, check laatste byte `0xbc`, split `maskedDB` & `H`, herstel $DB = \text{maskedDB} \oplus \text{MGF1}(H)$, check `padding2` (`00...00 01`), lees `salt`, herbereken $H' = H(\text{padding}_1 \mathbin{\|} H(M) \mathbin{\|} \text{salt})$, geldig als $H' == H$.
- **MGF1:** $T = H(X \mathbin{\|} 0) \mathbin{\|} H(X \mathbin{\|} 1) \mathbin{\|} \dots$ (32-bit big-endian counter), neem eerste $L$ bytes.

---

## 6. Mutual Trust, Key Distribution & Protocollen (Part 5)

### 6.1 Public Key Directory Spoofing & MitM

1. **Ongeauthenticeerde Public Directory / Announcement** (`PhoneBook`, slides 31–32):
   - **Kwetsbaarheid:** Iedereen kan een eigen public key registreren (of die van een slachtoffer overschrijven) zonder authenticatie.
   - **Aanval (`PhoneBook`):**
     ```python
     import requests, ast
     from Crypto.Util.number import long_to_bytes

     x = 123456789  # eigen willekeurige private key (1 < x < p-1)
     y = pow(g, x, p)
     # 1. Registreer eigen public key in de directory (of overschrijf doelwit)
     requests.post(f"{URL}/directory", json={"name": "target_or_me", "y": y})
     # 2. Laat server versleuteld bericht sturen en decrypt met eigen x
     res = requests.get(f"{URL}/send?to=target_or_me").json()
     s = pow(res["c1"], x, p)
     print(long_to_bytes((res["c2"] * pow(s, -1, p)) % p))
     ```

2. **Diffie-Hellman Key Exchange & MitM** (slides 23–25):
   - Basis: $Y_A = \alpha^{X_A} \bmod q$, $Y_B = \alpha^{X_B} \bmod q$, shared key $K = Y_B^{X_A} \equiv Y_A^{X_B} \pmod q$.
   - **MitM:** Darth onderschept $Y_A$ en $Y_B$, stuurt eigen $Y_{D1}$ naar Bob ($K_1 = Y_B^{X_{D1}}$) en $Y_{D2}$ naar Alice ($K_2 = Y_A^{X_{D2}}$). Darth decrypteert alles van Alice met $K_2$ en herversleutelt voor Bob met $K_1$.
   - **Subgroup / Weak Key Injectie (als server $Y$ niet valideert):**
     - Stuur $Y = 1 \implies$ shared key $K = 1^x \bmod p = 1$ (bekend!).
     - Stuur $Y = p - 1 \implies K \in \{1, p-1\}$ (slechts 2 mogelijkheden!).
     - Stuur $Y = 0 \implies K = 0$.

---

### 6.2 KDC, X.509 & Kerberos Aanvallen & Concepten

#### Aantal Master Keys (typische theorie-/protocolvraag)
- **Decentralized symmetric:** $\frac{N(N-1)}{2}$ master keys (elke host max $N-1$).
- **Centrale KDC:** $N$ master keys (één per host met KDC).
- **Kerberos inter-realm (v4):** $\frac{N(N-1)}{2}$ key exchanges tussen $N$ realms.

#### KDC & Replay Attacks (slides 17, 51–56)
- **Timeliness** tegen replay attacks via: sequence numbers (veel state), timestamps (kloksynchronisatie nodig), of challenge/response met **nonce**.
- **Klassieke KDC fout (slide 52):**
  - Stap 3: $A \to B: E(K_b, [K_s \mathbin{\|} ID_A])$.
  - Stappen 4 & 5 ($B \to A: E(K_s, N_2)$, $A \to B: E(K_s, f(N_2))$) voorkomen normale replay, **MAAR** als aanvaller een oude sessiesleutel $K_s$ kent, kan hij stap 3 replayen en zelf $f(N_2)$ antwoorden!
- **Oplossing (slide 55):** $B$ stuurt eerst een tijdslimiet $T_b$ (t.o.v. $B$'s eigen lokale klok, dus geen kloksynchronisatie nodig) mee in het ticket $E(K_b, [ID_A \mathbin{\|} K_s \mathbin{\|} T_b])$.

#### X.509 Public Key Certificates (slides 35–41)
- Certificaat van $A$ door CA: $C_A = E(PR_{\text{CA}}, [T \mathbin{\|} ID_A \mathbin{\|} PU_A])$ (in X.509: hash van velden gesigned met $PR_{\text{CA}}$).
- **CA Chain of Trust:** $Y\langle\langle X\rangle\rangle$ = certificaat van $X$ uitgegeven door $Y$.
  - Forward certificaat van $X$: uitgegeven door andere CA ($W\langle\langle X\rangle\rangle$).
  - Reverse certificaat van $X$: uitgegeven door $X$ voor andere CA ($X\langle\langle W\rangle\rangle$).
- **CRL (Certificate Revocation List):** lijst van ingetrokken maar nog niet verlopen certificaten (op serial number), gesigned door CA.
- **Waar op letten bij certificaat-challenges:**
  - Wordt de CA-handtekening überhaupt geverifieerd? (self-signed cert sturen!)
  - Wordt de `Subject` / `CN` / `Issuer` / geldigheidsperiode (`Not before` / `Not after`) / CRL gecheckt?

#### Kerberos v4 vs v5 (slides 57–65)
- **Flow (3 stappen, 100% symmetrisch):**
  1. `C <-> AS`: verkrijg **TGT** (`Ticket_tgs`, versleuteld met $K_{\text{tgs}}$) + sessiesleutel $K_{c,\text{tgs}}$ (versleuteld met $K_c$ afgeleid van wachtwoord).
  2. `C <-> TGS`: stuur `ID_v || Ticket_tgs || Authenticator_c` $\to$ krijg **Service Ticket** (`Ticket_v`, versleuteld met $K_v$) + $K_{c,v}$.
  3. `C <-> V`: stuur `Ticket_v || Authenticator_c` $\to$ optioneel mutual auth (`TS + 1` in v4; `TS` in v5).
- **Belangrijk:** Ticket is herbruikbaar (distribueert sleutel); **Authenticator** (`E(K_sess, [ID_c || AD_c || TS])`) bewijst identiteit en is eenmalig/kort geldig.
- **Kwetsbaarheden in v4 (opgelost in v5):**
  1. **DES** (zwak) $\to$ v5 ondersteunt elk algoritme.
  2. **PCBC mode** (kwetsbaar voor het verwisselen van ciphertext-blokken!) $\to$ v5 gebruikt CBC + expliciete checksum/hash.
  3. **Dubbele encryptie** van tickets in v4 $\to$ weg in v5.
  4. **Geen pre-authenticatie:** aanvaller kan AS-antwoord opvragen voor willekeurige gebruiker en offline wachtwoorden brute-forcen op $E(K_c, \dots)$ $\to$ v5 voegt pre-auth toe.
  5. **Geen sub-session keys:** hergebruik van $K_{c,v}$ over sessies $\to$ v5 voegt `SubKey` en `Seq #` toe.

---

## 7. Quick Checklist tijdens de Hacking Session

1. **Inspecteer eerst de cijfers:** print altijd `n.bit_length()`, `e`, `p.bit_length()`, `q.bit_length()`!
   - `n.bit_length() <= 100` $\rightarrow$ `sympy.factorint(n)` / `totient(n)`.
   - `e == 3` $\rightarrow$ check $c^{1/3}$ direct of CRT (Håstad).
   - `e.bit_length() > n.bit_length() // 2` $\rightarrow$ Wiener's attack!
   - Meerdere $n$'s $\rightarrow$ check paarsgewijs `math.gcd(ni, nj)`.
   - `p` en `g` aanwezig $\rightarrow$ ElGamal / DH / DSA! Check of `c1` gelijk is (nonce reuse), dichtbij is ($c_{1,2} \equiv c_{1,1} g^\Delta$, related nonce), of $p$ klein / $p-1$ smooth is (`discrete_log`).
   - `r` en `s` aanwezig $\rightarrow$ DSA! Check `r1 == r2` (nonce reuse) of kleine $\Delta$ (related nonce).
2. **Check de hash & encoding:**
   - Is $H(m)$ SHA-256 of SHA-1? `int.from_bytes(digest, "big") % q` of zonder `% q`?
   - Is de plaintext UTF-8, hex (`bytes.fromhex`), of `long_to_bytes`?
   - Bij blok-encryptie: vergeet `block_size` en `original_length` (padding) niet!
3. **Verifieer tussenstappen:**
   - RSA: `assert p * q == n` en `assert (e * d) % ((p-1)*(q-1)) == 1`
   - ElGamal / DSA: `assert pow(g, x, p) == y`
