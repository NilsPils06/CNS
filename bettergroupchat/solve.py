# Håstad's Broadcast Attack (e=3)
import binascii

def integer_cube_root(n):
    """Berekent de exacte integer derdemachtswortel met binary search."""
    low, high = 0, n
    while low < high:
        mid = (low + high) // 2
        if mid**3 < n:
            low = mid + 1
        else:
            high = mid
    return low

def egcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    """Berekent de modulaire inverse."""
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modulaire inverse bestaat niet')
    return x % m

def main():
    # De moduli uit public_keys.txt
    n1 = 6601514513649518920279892901564780522279009526315196379648408183598423266464743370237155844444550168426968544125632903695330764069391957257462703561896377
    n2 = 4758647878178723152629896429350683984908320113752214897868471446510112022142441754789895950762103788607490506293471670252683896806829881757270373888385173
    n3 = 6213681056262749062269306419456728479083164147822700073811694198951746102333940461427250166224159413319657684140862766752983555691560924447981288319056509

    # De versleutelde berichten uit ciphertexts.txt
    c1 = 4850370392558546246514347977200533994365629758026446799011726901926708724622211014226334371049610550361890519867189929979584471402256962154336291435115051
    c2 = 925617903172905686269738952522261745702184896278505458752644606331005606645434745821220926157589689810610208801632143105341568799172893809891456144217115
    c3 = 2994423788477786683957292040074194773241360803967764595369415279413166689378856118141236282313151996675193996235975547015423084485479505234160311764632711

    # Stap 1: Chinese Remainder Theorem (CRT) toepassen
    N = n1 * n2 * n3

    N1 = N // n1
    N2 = N // n2
    N3 = N // n3

    y1 = mod_inverse(N1, n1)
    y2 = mod_inverse(N2, n2)
    y3 = mod_inverse(N3, n3)

    # Vind C = m^3 mod N
    C = (c1 * N1 * y1 + c2 * N2 * y2 + c3 * N3 * y3) % N

    # Stap 2: Bereken de derdemachtswortel om m te vinden
    m = integer_cube_root(C)

    # Stap 3: Zet de integer om naar tekst
    hex_m = hex(m)[2:]
    # Zorg dat de string lengte even is
    if len(hex_m) % 2 != 0:
        hex_m = '0' + hex_m

    try:
        plaintext = binascii.unhexlify(hex_m).decode('utf-8')
        print("Gevonden plaintext:")
        print(plaintext)
    except Exception as e:
        print("Kan resultaat niet decoderen als UTF-8:", hex_m)

if __name__ == '__main__':
    main()
