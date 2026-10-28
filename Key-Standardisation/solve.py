#!/usr/bin/env python3
"""
Solution script voor de 'Key standardisation' challenge (CNS).

Uitleg van de kwetsbaarheid:
-----------------------------
1. DES (Data Encryption Standard) is een blokcijfer met een sleutellengte van 64 bits (8 bytes).
   Hiervan zijn slechts 56 bits effectieve sleutelbits; de minst significante bit (LSB)
   van elke byte is een pariteitsbit en wordt door DES genegeerd.
2. De maker heeft de sleutels 'gestandaardiseerd' met een vaste prefix ("namespace": "IOTDEV").
   "IOTDEV" is 6 bytes lang.
3. Hierdoor blijven er slechts 8 - 6 = 2 bytes over die variabel zijn!
   2 bytes = 256 * 256 = 65.536 mogelijke combinaties (en door de pariteitsbits zelfs nog minder effectieve sleutels).
4. Met een brute-force aanval kunnen we alle 65.536 mogelijkheden in minder dan een seconde proberen.
"""

import json
import sys
import time
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad


def solve():
    # 1. Lees de gegevens in uit key.json
    try:
        with open("key.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("[-] key.json niet gevonden!")
        sys.exit(1)

    namespace = data["namespace"].encode()
    ciphertext = bytes.fromhex(data["message"])

    print(f"[*] Namespace: {data['namespace']} (lengte: {len(namespace)} bytes)")
    print(f"[*] Ciphertext: {data['message']} (lengte: {len(ciphertext)} bytes)")
    print(f"[*] DES sleutellengte = 8 bytes. Onbekend: {8 - len(namespace)} bytes.")
    print("[*] Starten van brute-force...")

    start_time = time.time()
    first_block = ciphertext[:8]
    found_keys = []

    # Probeer namespace + 2 bytes (bijv. IOTDEV + "24")
    for b1 in range(256):
        for b2 in range(256):
            key_candidate = namespace + bytes([b1, b2])
            cipher = DES.new(key_candidate, DES.MODE_ECB)

            # Snelle controle op alleen het eerste blok (8 bytes)
            if cipher.decrypt(first_block).startswith(b"cns{"):
                plaintext = cipher.decrypt(ciphertext)
                try:
                    # PKCS#7 unpadding
                    unpadded = unpad(plaintext, DES.block_size).decode()
                except Exception:
                    unpadded = plaintext.decode(errors="replace")

                found_keys.append((key_candidate, unpadded))

    elapsed = time.time() - start_time
    print(f"[+] Brute-force voltooid in {elapsed:.3f} seconden.\n")

    if found_keys:
        print(f"[+] Gevonden vlag: {found_keys[0][1]}")
        print("[+] Mogelijke sleutels:")
        for key, _ in found_keys:
            print(f"    - {key} (hex: {key.hex()})")
        print("\n[i] Waarom meerdere sleutels werken:")
        print("    In DES is het 8e bit van elke byte een pariteitsbit dat genegeerd wordt.")
        print("    Daardoor leveren sleutels zoals 'IOTDEV24' en 'IOTDEV25' dezelfde subkeys op!")
    else:
        print("[-] Geen sleutel gevonden met namespace als prefix.")


if __name__ == "__main__":
    solve()
