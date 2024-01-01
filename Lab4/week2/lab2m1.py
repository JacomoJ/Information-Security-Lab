import json
import logging
import sys
import os
import socket
from sage.all import Zmod, Matrix, vector, ZZ, matrix
from schnorr import Schnorr, Schnorr_Params, Point
import random
# Change the port to match the challenge you're solving
PORT = 40210

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

# WRITE YOUR SOLUTION HERE

a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)
schnorr_inst = Schnorr(nistp256_params)

max_querries = 60

req = {
    "command": "get_pubkey"
}
json_send(req)
res = json_recv()
x = res['x']
y = res['y']
pubkey = Point(nistp256_params.curve, x, y)

t = []
txs = []
l_bits = 8
n_bits = 256

for i in range(max_querries):
    req = {
        "command": "get_signature",
        "msg": str(i)
    }
    json_send(req)
    res = json_recv()
    h = res['h']
    s = res['s']
    nonce = res['nonce']
    # a = nonce // (2**128)
    a = nonce >> (n_bits - l_bits)

    # as we seen in the lecture
    k = a * 2**(n_bits - l_bits) + 2**(n_bits - l_bits - 1)
    tx = (k-s) % nistp256_params.q
    if tx > int(nistp256_params.q / 2) - 1:
        tx = tx - q
    t.append(h)
    txs.append(tx)

# define the matrix
size = len(t) + 1
m = Matrix(ZZ, size, size)
factor = 2**(l_bits+1) # factor to have all integer entries
# diagonal
for i in range(size-1):
    m[i, i] = nistp256_params.q * factor
    m[size-1, i] = t[i] * factor
m[size-1,size-1] = 1

# map array to vector
us = vector(ZZ, size)
for i in range(len(txs)):
    us[i] = txs[i]

# final matrix to run LLL
M = 2**10
B = Matrix.block([[m, 0], [matrix(us), M]])
reduced_B = B.LLL()
target = "gimme the flag"

flag = ''
for i in reduced_B:
    for j in i:
        hash, s = schnorr_inst.Sign_Deterministic(int(j) % nistp256_params.q, target)
        req = {
            "command" : "solve", 
            "h": int(hash), 
            "s":int(s)
        }
        json_send(req)
        res = json_recv()
        if "flag" in res.keys():
            print(res)
            exit(0)
        hash, s = schnorr_inst.Sign_Deterministic(int(-j) % nistp256_params.q, target)
        req = {
            "command" : "solve", 
            "h": int(hash), 
            "s":int(s)
        }
        json_send(req)
        res = json_recv()
        if "flag" in res.keys():
            print(res)
            exit(0)
