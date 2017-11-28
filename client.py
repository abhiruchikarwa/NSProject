import socket
import argparse
import pickle
import threading
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import packet_pb2

parser = argparse.ArgumentParser()
# username as input
parser.add_argument('-u', type = str, help = 'input username', action = 'store')
args = parser.parse_args()

with open('config.json') as json_data_file:
    configdict = json.load(json_data_file)

# print args

# values taken as input assigned to variables
UN = args.u
SIP = configdict["ipaddr"]
UDP_PORT = configdict["port"]
pubkey_path = configdict["pubkey"]
base = configdict["base"]
p = configdict["p"]


# lists for storing data from the pickle file
names = []
addr = []
port = []

# solving the challenge sent by the server
def solvechallenge(c):
    return c & 0xfffffff

# use serverkeyencryption(public_key_loading(pubkey_path), msg) to encrypt the msg with server's public key

def public_key_loading(key):
    # loads the public key in .der format into a variable and returns it
    with open(key, "rb") as key_file:
        public_key = serialization.load_der_public_key(
            key_file.read(),
            backend=default_backend())
        return public_key


def serverkeyencryption(public_key, var):
    # encrypts the received variable using the received public key
    en_var = public_key.encrypt(var, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None))
    # returns the encrypted  variable
    return en_var


####################################################
# Function to authenticate the server
# Changes made today by Ketan
def autheticatedlogin(uname, pswd):
    w = func(pswd);
    # send login request to the server
    pkt1 = packet_pb2.Packet()
    pkt1.msgType = "Login"
    pkt1.smsg.stepNumber = 1
    pkt1.smsg.actMsg = "Dummy message"

    sendpacket(pkt1.SerializeToString(), "127.0.0.1", 9090);

def  func(pswd):
    return pswd+"what"

####################################################
# function to send packets to anyone
def sendpacket(packet, sip, sport):
    BUFFER_SIZE = 1024
    while packet:
        sentbytes = sc.sendto(packet[:BUFFER_SIZE], (sip, sport))
        packet = packet[sentbytes:]


# function to receive packets from anywhere.
def receivepacket():
    while True:
        # to receive data
        rdata, adr = sc.recvfrom(1024)
        if not rdata:
            chat()
        print 'received data: ' + rdata


def sendmsg(smsg):
    # removing the command from the original message
    smsg = smsg[5:]
    # extracting receiver's name
    rec = smsg.partition(' ')[0]
    # ###print rec
    # to send data to the receiver
    smsg = smsg[(len(rec) + 1):]
    # ###print msg
    # getting the place of user item in 'names' list
    i = names.index(rec)
    # making variables for receiver's ip-address and port
    RIP = addr[i]
    R_PORT = port[i]
    BUFFER_SIZE = 1024
    while smsg:
        sentbytes = sc.sendto(smsg[:BUFFER_SIZE], (RIP, R_PORT))
        smsg = smsg[sentbytes:]


def getlist():
    try:
        with open('users.json', 'rb') as user_data:
            userdict = json.load(user_data)
        return userdict
    except EOFError:
        pass

# basic function
def chat():
    while 1:
        # starting the message receiving thread
        rt = threading.Thread(target=receivepacket)
        rt.start()

        msg = raw_input('+>')

        # extracting the command
        cmd = msg.partition(' ')[0]

        if cmd == "list":
            userlist = getlist()
            for key, value in userlist.items():
                if value["conn"] == 1:
                    print key

        elif cmd == "send":
            try:
                # starting the message sending thread
                st = threading.Thread(target=sendmsg(msg))
                st.start()
                # sendmsg(msg)
            except socket.error as emsg:
                print 'Error: ' + str(emsg)

        elif cmd == "connect":
            print "connect"

        elif cmd == "disconnect":
            print "disconnect"



        else:
            print 'Incorrect command/message'


# socket creation
if __name__ == "__main__":
    try:
        sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sc.connect((SIP, UDP_PORT))
    except socket.error, msg:
        print 'Socket creation failed' + msg
    chat()
    # calling the actual chat function to perform tasks
    autheticatedlogin("Ketan", "pwd")
    # closing connection
    sc.close