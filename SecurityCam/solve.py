import hashlib

username = "user"
realm = "PythonRTSP"
nonce = "4874a055c3f4390506d99e6c51a9e3e360cbef8a62abd7079e11faddcb70a38c"
method = "DESCRIBE"
uri = "rtsp://cns-test.idlab.uantwerpen.be:50002/video"
target_response = "b3539154c5b784bba2c47a1a6c7c4ab0"

# HA2 is constant voor alle wachtwoorden
ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

print("Lokaal zoeken in rockyou.txt...")
with open("rockyou.txt", "r", encoding="latin-1") as f:
    for idx, line in enumerate(f):
        password = line.strip()
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

        if response == target_response:
            print(f"Gevonden op regel {idx + 1}: {password}")
            break
