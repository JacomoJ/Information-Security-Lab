#%%
import json
import logging
import sys
import os
import socket 
from sage.all import Zmod, matrix, vector, PolynomialRing, inverse_mod, ZZ, ideal, QQ, Sequence, Matrix

# Change the port to match the challenge you're solving
PORT = 40300

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
N_BIT_LENGTH = 1024

req = {
    "command": "get_pubkey"
}
json_send(req)
res = json_recv()
n = int(res['n'])
e = int(res['e'])
# print('n: ', n)
# print('e: ', e)

Zn = Zmod(n)

req = {
    "command": "get_ciphertext"
}
json_send(req)
res = json_recv()
ctxt = bytes.fromhex(res['ciphertext'])
ctxt_int = int.from_bytes(ctxt)

#%%
# why we are considering the length of hex instead of bytes.fromhex(msg)
msg_len = 16
# but we have to add length of one byte for padding
pad_len = N_BIT_LENGTH // 8 - (msg_len + 1) # == 111
padding = bytes([pad_len] * pad_len)
padding_int = Zn(int.from_bytes(padding))
# shift the x all the way to the left so we can append the padding
shift = 2**(pad_len*8)


#%%  
X = 2**(msg_len*8)

R = PolynomialRing(ZZ, 1, 'x')
x = R.gen()
P = (x * shift + padding_int)**e - ctxt_int
# lead_coeff = P.coefficient(x**3)
# P = P.monic()
# print(P.small_roots())
# P = P // lead_coeff

# P = P.change_ring(ZZ)
# coeffs = P.coefficients(sparse=False)

S = Sequence([], R)
S.append(((x * shift + padding_int)**3 - ctxt_int) // shift**3)
coefficients, _ = S.coefficient_matrix(sparse=False)
coeffs = coefficients[0]
a0 = coeffs[3]
a1 = coeffs[2]
a2 = coeffs[1]

m = matrix(ZZ, [
    [n, 0, 0, 0],
    [0, n*X, 0, 0],
    [0, 0, n*X**2, 0],
    [a0, a1*X, a2*X**2, X**3] # leading coeff == 1
])

reduced_B = m.LLL()
first_row = reduced_B[0]

R2 = PolynomialRing(ZZ, 1, 'x')
w = R2.gen()
sol = first_row[0]
for i in range(1, len(first_row)):
    sol += ZZ(first_row[i] / X**i) * w**i
I = ideal(sol.change_ring(QQ))
root = I.variety(ring=ZZ)[0]['x']

root = int(root).to_bytes(msg_len, 'big')
root = root.decode()
req = {
    "command": "solve",
    "message": root
}
json_send(req)
res = json_recv()
print(res)

# sol_a1 = first_row[1] / X
# sol_a2 = first_row[2] / (X**2)
# sol_a3 = first_row[3] / (X**3)
# sol = sol_a0 + sol_a1 * g + sol_a2*(g**2) + sol_a3*(g**3)
