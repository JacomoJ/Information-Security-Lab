# %%
import json
import logging
import sys
import os
import socket
from ecdsa2 import Point, get_nistp256, bits_to_int, hash_message_to_bits, ECDSA2, ECDSA2_Params
from sage.arith.misc import inverse_mod
from time import time, sleep
# Change the port to match the challenge you're solving
PORT = 40120

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


# %%

# WRITE YOUR SOLUTION HERE
a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = ECDSA2_Params(a, b, p, P_x, P_y, q)
ecdsa = ECDSA2(nistp256_params)

req = {
    "command": "get_pubkey"
}
json_send(req)
res = json_recv()
pub_key = Point(ecdsa.curve, res['x'], res['y'])

msg1 = "To X."
msg2 = "2023"
h_msg1 = bits_to_int(hash_message_to_bits(msg1), ecdsa.q)
h_msg1 = ecdsa.Z_q(h_msg1)
h_msg2 = bits_to_int(hash_message_to_bits(msg2), ecdsa.q) 
h_msg2 = ecdsa.Z_q(h_msg2)

req1 = {
    "command": "get_signature",
    "msg": msg1
}
req2 = {
    "command": "get_signature",
    "msg": msg2
}

json_send(req1)
json_send(req2)

res = json_recv()
r1 = ecdsa.Z_q(res['r'])
s1 = ecdsa.Z_q(res['s'])
res = json_recv()
r2 = ecdsa.Z_q(res['r'])
s2 = ecdsa.Z_q(res['s'])

k = ecdsa.Z_q((h_msg1**2 - h_msg2**2) / (s1 - s2))
priv_key = ecdsa.Z_q((k * s1 - h_msg1**2) / (r1 * 1337))

target_msg = "gimme the flag"
target_r, target_s = ecdsa.Sign_FixedNonce(k, priv_key, target_msg)
req = { 
    "command": "solve",
    "r": int(target_r),
    "s": int(target_s)
}
json_send(req)
print(json_recv())



