import json, random, string, datetime, hashlib
from datetime import timezone

def canonicalize(payment):
    return json.dumps(
        payment,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

def generate_payment6():
    timestamp = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    amount = 10
    currency = "EUR"
    from_acc = "SIM-6"
    to_acc = "SIM-7"
    reference = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    return {"reference":reference, "from_account":from_acc, "to_account":to_acc,"amount":amount,"currency":currency, "timestamp":timestamp}

def generate_payment7():
    timestamp = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    amount = 10
    currency = "EUR"
    from_acc = "SIM-7"
    to_acc = "SIM-6"
    reference = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    return {"reference":reference, "from_account":from_acc, "to_account":to_acc,"amount":amount,"currency":currency, "timestamp":timestamp}

def find_collision():
    hashes = dict()
    while True:
        payment1 = generate_payment6()
        payment2 = generate_payment7()
        p1 = hashlib.sha256(canonicalize(payment1)).hexdigest()
        p1 = p1[:8]
        hashes[p1] = payment1

        p2 = hashlib.sha256(canonicalize(payment2)).hexdigest()
        p2 = p2[:8]
        if p2 in hashes and hashes[p2]["reference"] != payment2["reference"]:
            return (canonicalize(hashes[p2]), canonicalize(payment2))

print(find_collision())
