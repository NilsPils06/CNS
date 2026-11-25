import requests, ast
from Crypto.Util.number import long_to_bytes

g = 2
p = 7307846879904189030929679948466541795201493576644000827516745178921657491638900092075124066074860350245731460646064790947916261089076564811441840899544337
x = 546174652041363726165206973207468652062657374206172746973742065766572
y = pow(g, x, p)
json_obj = {"name": "y4b01", "y": y}

# requests.post(url="http://cns-test.idlab.uantwerpen.be:50011/directory", json=json_obj)

response = requests.get(url="http://cns-test.idlab.uantwerpen.be:50011/send?to=y4b01").text
res = ast.literal_eval(response)
s = pow(res['c1'], x, p)
m = res['c2'] * pow(s, -1, p) % p
m = long_to_bytes(m)
print(m.decode())
