import base64
import json
import socket
import sys
import threading
import ast
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import packet_pb2
import os
import random

challenges = {}
temp_values = {}
connected_users = {}
currusers = {}

with open('sconf.json') as json_data_file:
    configdict = json.load(json_data_file)

base = configdict["base"]
p = int(configdict["p"])
IP_ADDR = configdict["ipaddr"]
UDP_PORT = configdict["port"]


# use serverkeydecryption(private_key_loading(prikey_path), msg) to decrypt the msg with server's private key

with open('users.json') as json_data_file:
    users = json.load(json_data_file)

# Message Packet for Authentication
pkt1 = packet_pb2.Packet()

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

def solvechallenge(c):
    return int(c, 0) & 0xfffffff

def sendpacket(packet, sip, sport):
    # BUFFER_SIZE = 1024
    ss.sendto(packet, (sip, sport))
    # packet = packet[sentbytes:]

def fillauthpacket(pkt, msgtype, step, mesg):
    try:
        pkt.msgType = msgtype
        pkt.smsg.stepNumber = step
        pkt.smsg.actMsg = mesg
    except:
        print "Exception thrown in fillauthpacket"

def handleloginrequest(addr):
    challenge = generatechallenge()

    challenges[addr] = challenge

    fillauthpacket(pkt1, "Login", 2, challenge)

    sendpacket(pkt1.SerializeToString(), addr[0], addr[1])

def challengeresponsevalidation(recvchall, addr, apkt1):
    rdict = ast.literal_eval(apkt1.smsg.actMsg)
    solvedchallenge = rdict["solvedChallenge"]

    if solvedchallenge == solvechallenge(recvchall):
        rdict = ast.literal_eval(
            serverkeydecryption(private_key_loading("prikey.pem"), base64.b64decode(rdict["edict"])))
        uid = rdict["id"]
        clientcontri = rdict["DH"]

        if uid not in currusers:
            if uid in users:
                if clientcontri != 0:
                    secret = users[uid]["passwd"]
                    b = int(random.getrandbits(32))
                    u = int(random.getrandbits(32))
                    C2 = int(random.getrandbits(32))

                    sumcontri = pow(base, b, p) + long(secret)
                    numbers = {"sum": sumcontri, "num_Server": u, "C2": C2}
                    # print secret

                    retdict = {"uname": uid, "secret": secret, "u": u, "clientcontri": clientcontri, "b": b, "C2": C2,
                               "sumcontri": sumcontri}
                    temp_values[addr] = retdict

                    fillauthpacket(apkt1, "Login", 4, bytes(numbers))
                    sendpacket(apkt1.SerializeToString(), addr[0], addr[1])
            else:
                print "Unregistered user trying to log in"
                fillauthpacket(apkt1, "Login", 4, "unregistered")
                sendpacket(apkt1.SerializeToString(), addr[0], addr[1])
        else:
            print "Someone is trying to log in from a different address"
            fillauthpacket(apkt1, "Login", 4, "preregistered")
            sendpacket(apkt1.SerializeToString(), addr[0], addr[1])
    else:
        print "DOS Alert!"

def authlaststep(d, addr, aupkt1):
    # print d
    # print "cc:", d["clientcontri"]
    # print "secret:", d["secret"]
    # print "sc:", d["sumcontri"]
    session_key = pow(pow(long(d["clientcontri"]), long(d["b"]), p) * pow(long(d["secret"]), (d["b"]*d["u"]), p), 1, p)
    # print "sk:", session_key

    batch = ast.literal_eval(aupkt1.smsg.actMsg)
    # print "batch", batch

    ct = batch["Enc"]
    # print "ct", ct
    C3 = batch["C3"]
    # print 'c3', C3
    nonce = batch["nonce"]
    # print "nonce", nonce
    salt = batch["salt"]
    # print "salt", salt

    c2 = d["C2"]

    backend = default_backend()
    # derive
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=backend)

    key = kdf.derive(bytes(session_key))
    # print "key", key

    aesgcm = AESGCM(key)
    try:
        ct = long(aesgcm.decrypt(nonce, ct, None))
        if c2 == ct:
            # print "values match"
            nonce2 = os.urandom(12)
            encc3 = aesgcm.encrypt(nonce2, bytes(C3), None)
            # print "enc okay"
            retd = {"encc3": encc3,
                    "nonce2": nonce2}
            fillauthpacket(aupkt1, "Login", 6, bytes(retd))
            # print "pf"
            sendpacket(aupkt1.SerializeToString(), addr[0], addr[1])
            # print "6 sent"
            connected_users[addr] = {"uname": temp_values[addr]["uname"],
                                     "ipaddr": addr[0],
                                     "port": addr[1],
                                     "skey": key}
            currusers[temp_values[addr]["uname"]] = {"ipaddr": addr[0],
                                                     "port": addr[1]}
            del temp_values[addr]
    except cryptography.exceptions.InvalidTag:
        print "Someone entered an incorrect password"
        fillauthpacket(aupkt1, "Login", 6, "Incorrect")
        sendpacket(aupkt1.SerializeToString(), addr[0], addr[1])

def loginfunction(addr, lpkt1):
    if lpkt1.smsg.stepNumber == 1 and lpkt1.msgType == "Login" and lpkt1.smsg.actMsg == "Login":
        # print "on step 1"
        handleloginrequest(addr)

    elif lpkt1.smsg.stepNumber == 3 and lpkt1.msgType == "Login":
        # print "on step 3"
        if addr in challenges:
            challengeresponsevalidation(challenges.get(addr), addr, lpkt1)
        else:
            "DOS attack"
    elif lpkt1.smsg.stepNumber == 5 and lpkt1.msgType == "Login":
        # print "on step 5"
        authlaststep(temp_values.get(addr), addr, lpkt1)
    else:
        print "else clause"

def listfunction(listaddr, listpkt1):
    if listpkt1.smsg.stepNumber == 1:
        listdict = ast.literal_eval(listpkt1.smsg.actMsg)
        nonce = listdict["nonce"]
        edict = listdict["edict"]

        key = connected_users[listaddr]["skey"]
        aesgcm = AESGCM(key)
        try:
            ct = ast.literal_eval(aesgcm.decrypt(nonce, edict, None))
            if ct["msg"] == "list":
                # print "in list"

                nonce2 = int(ct["ts"]) + 1
                rdict = {"list": currusers,
                         "nonce2": nonce2}
                nonce3 = os.urandom(12)
                emsg = aesgcm.encrypt(nonce3, bytes(rdict), None)
                # print "enc okay"
                retd = {"emsg": emsg,
                        "nonce3": nonce3}
                fillauthpacket(listpkt1, "List", 2, bytes(retd))
                # print "pf"
                sendpacket(listpkt1.SerializeToString(), listaddr[0], listaddr[1])
                # print "list sent"
        except cryptography.exceptions.InvalidTag:
            print "decrypt not okay"
            # fillauthpacket(listpkt1, "List", 2, "Incorrect")
            # sendpacket(listpkt1.SerializeToString(), listaddr[0], listaddr[1])

def keyeststep5(claddr, clpkt1):

    Session_Key_A = connected_users[claddr]["skey"]

    dict6 = ast.literal_eval(serverkeydecryption
                             (private_key_loading("prikey.pem"), base64.b64decode(clpkt1.smsg.actMsg)))
    Na = dict6["Na"]
    A = dict6["A"]
    addr_B = dict6["Baddr"]
    B = dict6["B"]
    Session_Key_B = connected_users[addr_B]["skey"]
    enc_credentials = ast.literal_eval(dict6["pack"])

    aesgcm = AESGCM(Session_Key_B)
    try:
        Nb = aesgcm.decrypt(enc_credentials["nonce"], enc_credentials["ct"], None)
    except cryptography.exceptions.InvalidTag:
        print "Decryption incorrect"
        # fillauthpacket(clpkt1, "KEY_EST", 6, "Incorrect")
        # sendpacket(clpkt1.SerializeToString(), claddr[0], claddr[1])
    # Generate Ticket-to-B
    # Generate a Session Key for A-B Communication
    Sab = AESGCM.generate_key(bit_length=128)
    ticket = {"Sab": Sab,
              "A": A,
              "Aaddr":claddr,
              "Nb": Nb}
    nticket = os.urandom(12)

    ticket_to_B = aesgcm.encrypt(nticket, bytes(ticket), None)

    # iv_for_ticket, ticket_to_B, tag_for_ticket = encrypt(Session_Key_B, ticket, "")
    packet = {"Na": Na,
              "B": B,
              "Baddr": addr_B,
              "Sab": Sab,
              "ticket_to_B": ticket_to_B,
              "nticket": nticket}
    aesgcm = AESGCM(Session_Key_A)
    noncefora = os.urandom(12)
    enc_packet = aesgcm.encrypt(noncefora, bytes(packet), None)

    step6output = {"noncefora": noncefora,
                   "enc_packet": enc_packet}
    fillauthpacket(clpkt1, "KEY_EST", 6, bytes(step6output))
    sendpacket(clpkt1.SerializeToString(), claddr[0], claddr[1])

def ssfunction(claddr, clpkt1):
    if clpkt1.smsg.stepNumber == 1:
        listdict = ast.literal_eval(clpkt1.smsg.actMsg)
        nonce = listdict["nonce"]
        edict = listdict["edict"]

        key = connected_users[claddr]["skey"]
        aesgcm = AESGCM(key)
        try:
            ct = ast.literal_eval(aesgcm.decrypt(nonce, edict, None))
            if ct["msg"] == "list":
                nonce2 = int(ct["ts"]) + 1
                rdict = {"list": currusers,
                         "nonce2": nonce2}
                nonce3 = os.urandom(12)
                emsg = aesgcm.encrypt(nonce3, bytes(rdict), None)
                retd = {"emsg": emsg,
                        "nonce3": nonce3}
                fillauthpacket(clpkt1, "KEY_EST", 2, bytes(retd))
                sendpacket(clpkt1.SerializeToString(), claddr[0], claddr[1])

        except cryptography.exceptions.InvalidTag:
            print "decrypt not okay"
            # fillauthpacket(clpkt1, "KEY_EST", 2, "Incorrect")
            # sendpacket(clpkt1.SerializeToString(), claddr[0], claddr[1])

    elif clpkt1.smsg.stepNumber == 5:
        keyeststep5(claddr, clpkt1)

def logoutfunction(lgaddr, lgpkt1):
    if lgpkt1.smsg.stepNumber == 1:
        packet = ast.literal_eval(lgpkt1.smsg.actMsg)
        ct = packet["ct"]
        nonce = packet["nonce"]
        key = connected_users[lgaddr]["skey"]
        aesgcm = AESGCM(key)
        try:
            val = ast.literal_eval(aesgcm.decrypt(nonce, ct, None))
            if connected_users[lgaddr]["uname"] == val["uname"]:
                # forget all values pertaining to this user
                del connected_users[lgaddr]
                del challenges[lgaddr]
                del currusers[val["uname"]]
                # print "user removed!"
            else:
                print "Someone tried to log out:", val["uname"]

            non = os.urandom(12)
            newNl = int(val["Nl"]) + 1
            ct1 = aesgcm.encrypt(non, bytes(newNl), None)
            pack = {"nonce": non,
                    "ct": ct1}
            fillauthpacket(lgpkt1, "LOGOUT", 2, bytes(pack))
            sendpacket(lgpkt1.SerializeToString(), lgaddr[0], lgaddr[1])
            # print "user logged out"
        except cryptography.exceptions.InvalidTag:
            print "decrypt not okay"
            # fillauthpacket(lgpkt1, "LOGOUT", 2, "Incorrect")
            # sendpacket(lgpkt1.SerializeToString(), lgaddr[0], lgaddr[1])

def recievepacket(ss):
    # data, addr = ss.recvfrom(1024)
    # return {"data": data,
    #         "addr": addr}
    while True:
        try:
            maxpkglen = 1024*1024
            # to receive data
            # print "in receive"

            ss.settimeout(30.0)
            data, addr = ss.recvfrom(maxpkglen)
            if data:
                pkt1.ParseFromString(data)

                if pkt1.msgType == "Login":
                    loginfunction(addr, pkt1)
                elif pkt1.msgType == "List":
                    listfunction(addr, pkt1)
                elif pkt1.msgType == "KEY_EST":
                    ssfunction(addr, pkt1)
                elif pkt1.msgType == "LOGOUT":
                    print "Logout request received from:", connected_users[addr]["uname"]
                    logoutfunction(addr, pkt1)
        except socket.error:
            print "Still receiving data"


if __name__ == '__main__':
    try:
        ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # bind the socket to the IP address and Port given
        ss.bind((IP_ADDR, UDP_PORT))
        print "Server Initialized..."

    except socket.error, msg:
        print "Socket creation failed:", msg
        sys.exit()

    rt = threading.Thread(target=recievepacket, args=(ss,))
    rt.start()