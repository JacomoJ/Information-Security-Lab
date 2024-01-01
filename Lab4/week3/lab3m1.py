#%%
import json
import logging
import sys
import os
import socket 
from sage.all import Zmod, matrix, vector, PolynomialRing, inverse_mod, ZZ, ideal, QQ, Sequence, Matrix
import math
from Crypto.Hash import SHA256

# Change the port to match the challenge you're solving
PORT = 40310

# Pro tip: for debugging, set the level to logging.DEBUG if you want
# to read all the messages back and forth from the server
# log_level = logging.DEBUG
log_level = logging.INFO
logging.basicConfig(stream=sys.stdout, level=log_level)

s = socket.socket()

# Set the environmental variable REMOTE to True in order to connect to the server
#
# To do so, run on the terminal:
# REMOTE=True sage solve.py
#
# When we grade, we will automatically set this for you
if "REMOTE" in os.environ:
    s.connect(("isl.aclabs.ethz.ch", PORT))
else:
    s.connect(("localhost", PORT))
# s.connect(("isl.aclabs.ethz.ch", PORT))
fd = s.makefile("rw")


def json_recv():
    """Receive a serialized json object from the server and deserialize it"""

    line = fd.readline()
    logging.debug(f"Recv: {line}")
    return json.loads(line)

def json_send(obj):
    """Convert the object to json and send to the server"""

    request = json.dumps(obj)
    logging.debug(f"Send: {request}")
    fd.write(request + "\n")
    fd.flush() 

#%%  
# WRITE YOUR SOLUTION HERE
bit_lengths = {
    '512': 512,
    '1024': 1024,
    '2048': 2048
}

req = {
    "command": "gen_key",
    "bit_length": bit_lengths['512'],
    "identifier": 1
}
json_send(req)
res = json_recv()
print(res)
req = {
    "command": "gen_key",
    "bit_length": bit_lengths['2048'],
    "identifier": 1
}
json_send(req)
res = json_recv()
print(res)

req = {
    "command": "get_pubkey",
    "identifier": 1
}
json_send(req)
res = json_recv()
n = int(res['n'])
e = int(res['e'])
bits = int(res['bits'])


req = {
    "command": "export_p",
    "identifier": 1
}
json_send(req)
res = json_recv()
nonce = res['nonce']
p_leak = res['obfuscated_p']

len_obf = 512 // 2
p_leak = int(bytes.fromhex(p_leak)[len_obf:], 2)

R = PolynomialRing(ZZ, 1, 'x')
x = R.gen()
P = p_leak * pow(2**(1024 - 256), -1, n) + x

# parameters according to the theorem in chapter 19.4
beta = 0.5
eps = beta / 7
h = math.ceil(max(4, 1 / (4 * eps)))
k = 2*h
X = 2**256

S = Sequence([], R)
for i in range(h):
    S.append(n**(h-i) * P**(i))
for i in range(h+1):
    S.append(x**i * P**h)
coeff_matrix, _ = S.coefficient_matrix(sparse=False)

B = Matrix(ZZ, k+1, k+1)
for j in range(k+1):
    for i in range(k+1):
        B[i, j] = coeff_matrix[i][k-j] * X**j
reduced_B = B.LLL()

P2 = sum([(reduced_B[0, i] // X**i) * x**i for i in range(B.ncols())])
I = ideal(P2.change_ring(QQ))
root = I.variety(ring=ZZ)[0]['x']

p = root * 2**(1024 - 256) + p_leak

hash = SHA256.new(b'gimme the flag').digest()
hash_int = int.from_bytes(hash, 'big')
q = n // p
phi = (p-1) * (q-1)
d = pow(e, -1, phi)
signature = pow(hash_int, d, n)
req = {
    "command": "solve",
    "identifier": 1,
    "signature": str(signature)
}
json_send(req)
print(json_recv())