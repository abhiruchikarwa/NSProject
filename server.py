import json
import socket
import sys
import os
import pickle
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import cryptography.exceptions

IP_ADDR = '0.0.0.0'
UDP_PORT = 9090

# creating a socket
# parameters: domain, type, protocol(optional)
# domain here is IP(AF_INET), can be IPv6(AF_INET6)
# type is SOCK_DGRAM(user datagram protocol)

with open('sconf.json') as json_data_file:
    configdict = json.load(json_data_file)

prikey_path = configdict["prikey"]

# use serverkeydecryption(private_key_loading(prikey_path), msg) to decrypt the msg with server's private key

def private_key_loading(key):
    # loads the private key in .pem format into a variable and returns it
    with open(key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())
        return private_key


def serverkeydecryption(private_key, var):
    # decrypts the received variable using the received private key.
    de_var = private_key.decrypt(var, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None))
    # returns the decrypted  variable
    return de_var


# random 128 bit number generator
def generatechallenge():
    return hex(random.getrandbits(128))


try:
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    open('clients.pkl', 'w')
    print "Server Initialized..."
except socket.error, msg:
    print "Socket creation failed" + msg
    sys.exit()

# bind the socket to the IP address and Port given
ss.bind((IP_ADDR, UDP_PORT))

while 1:
    data, addr = ss.recvfrom(1024)
    if os.path.exists('clients.pkl'):
        # append if already exists
        action = 'ab'
    else:
        # make a new file if not
        action = 'wb'
    with open('clients.pkl', action) as f:
        pickle.dump(data, f)
        pickle.dump(addr[0], f)
        pickle.dump(addr[1], f)
            
    # breaks connection after data has been sent completely
    if not data:
        break

# closing connection
ss.close