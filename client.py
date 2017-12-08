import ast
import base64
import socket
import threading
import json

import cryptography
import queue
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import random
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import pprint
import packet_pb2
import hashlib
with open('config.json') as json_data_file:
    configdict = json.load(json_data_file)

# values taken as input assigned to variables
SIP = configdict["ipaddr"]
UDP_PORT = configdict["port"]
base = configdict["base"]
p = int(configdict["p"])

rdata = 0
addr = 0
r = 0
# lists for storing data from the pickle file
temp = {}
known_users = {}
temp_known_users = {}
# Message Packet for Authentication
pkt1 = packet_pb2.Packet()

# Password Secret
def func(password):
    s = int(hashlib.sha256(password).hexdigest(), 16)
    return s

# solving the challenge sent by the server
def solvechallenge(c):
    return int(c, 0) & 0xfffffff

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
    return bytes(en_var)

def sendloginrequest():
    # send login request to the server
    fillauthpacket(pkt1, "Login", 1, "Login")
    sendpacket(pkt1.SerializeToString(), SIP, UDP_PORT)

def receivechallengesendresponse(username, apkt1):

    # Random Number from a:
    receivechallengesendresponse.a = int(random.getrandbits(32))

    # receive challenge from server
    challenge = apkt1.smsg.actMsg
    # generate DH Contribution
    contri = pow(base, receivechallengesendresponse.a, p)

    # create a dictionary with the uname, DH Contribution and solved challenge
    authdict = {"id": username,
                "DH": contri}

    en_dict = serverkeyencryption(public_key_loading("pubkey.der"), bytes(authdict))

    actdict = {"edict": base64.b64encode(en_dict),
               "solvedChallenge": solvechallenge(challenge)}

    fillauthpacket(apkt1, "Login", 3, bytes(actdict))

    sendpacket(apkt1.SerializeToString(), SIP, UDP_PORT)

def receivecontricalsessionkey(upswd, aupkt1):

    # receive the numbers (server contri, u and a challenge)
    numbers = ast.literal_eval(aupkt1.smsg.actMsg)
    servercontri = numbers["sum"]
    u = numbers["num_Server"]
    C2 = numbers["C2"]
    w = func(upswd)
    if u != 0:
        secret = pow(base, w, p)
        serverContri = servercontri - secret
        if serverContri != 0:
            power = receivechallengesendresponse.a + u * w
            session_key = pow(pow(serverContri, power, p), 1, p)

            receivecontricalsessionkey.C3 = int(random.getrandbits(32))

            backend = default_backend()
            salt = os.urandom(16)
            # derive
            kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=backend)

            key = kdf.derive(bytes(session_key))
            temp["sk"] = key
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, bytes(C2), None)
            batch = {"Enc": ct,
                     "C3": receivecontricalsessionkey.C3,
                     "nonce": nonce,
                     "salt": salt}
            fillauthpacket(aupkt1, "Login", 5, bytes(batch))
            sendpacket(aupkt1.SerializeToString(), SIP, UDP_PORT)

def srplaststep(autpkt1):
    # receive the encrypted C3
    retd = ast.literal_eval(autpkt1.smsg.actMsg)
    ct = retd["encc3"]
    nonce = retd["nonce2"]
    key = temp["sk"]

    aesgcm = AESGCM(key)
    try:
        ct = long(aesgcm.decrypt(nonce, ct, None))
        if receivecontricalsessionkey.C3 == ct:
            print "You are now authenticated"
            del receivechallengesendresponse.a
            return 1
        else:
            print "Server invalid"
            return -1
    except cryptography.exceptions.InvalidTag:
        return -1

def fillauthpacket(pkt, msgtype, step, messg):
    pkt.msgType = msgtype
    pkt.smsg.stepNumber = step
    pkt.smsg.actMsg = messg

# function to send packets to anyone
def sendpacket(packet, sip, sport):
    BUFFER_SIZE = 1024
    while packet:
        sentbytes = sc.sendto(packet[:BUFFER_SIZE], (sip, sport))
        packet = packet[sentbytes:]

def getlist():
    ts = random.getrandbits(8)
    temp["ts"] = ts
    listdict = {"msg": "list",
                "ts": ts}
    # print "dict okay"
    aesgcm = AESGCM(temp["sk"])
    # print aesgcm
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, bytes(listdict), None)
    # print "encryption okay"
    batch = {"edict": ct,
             "nonce": nonce}
    # print "batch okay"
    fillauthpacket(pkt1, "List", 1, bytes(batch))
    sendpacket(pkt1.SerializeToString(), SIP, UDP_PORT)

    # data, adr = sc.recvfrom(1024)
    # pkt1.ParseFromString(data)

def recvlist():
    if pkt1.smsg.stepNumber == 2:
        recdict = ast.literal_eval(pkt1.smsg.actMsg)
        nonce3 = recdict["nonce3"]
        emsg = recdict["emsg"]

        aesgcm = AESGCM(temp["sk"])
        try:
            ct = aesgcm.decrypt(nonce3, emsg, None)
            actdict = ast.literal_eval(ct)
            reclist = actdict["list"]
            nonce2 = actdict["nonce2"]
            ts = temp["ts"]

            if nonce2 == int(ts) + 1:
                del temp["ts"]
                return reclist
            else:
                return "list incorrect"
        except cryptography.exceptions.InvalidTag:
            print "Decrypt not okay"

    else:
        print "Server sent an incorrect packet"

def keyeststep1():
    ts = random.getrandbits(8)
    temp["ts"] = ts
    step1dict = {"msg": "list",
                 "ts": ts}
    aesgcm = AESGCM(temp["sk"])
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, bytes(step1dict), None)
    batch = {"edict": ct,
             "nonce": nonce}
    fillauthpacket(pkt1, "KEY_EST", 1, bytes(batch))
    sendpacket(pkt1.SerializeToString(), SIP, UDP_PORT)

def keyeststep2():
    keyestfunction.availusers = recvlist()
    keyeststep2.smsg = chat.message[5:]
    # extracting receiver's name
    keyestfunction.rec = keyeststep2.smsg.partition(' ')[0]
    keyestfunction.smsg = keyeststep2.smsg[(len(keyestfunction.rec) + 1):]
    if keyestfunction.rec in keyestfunction.availusers:
        sendfunction(keyestfunction.rec, keyestfunction.availusers)
    else:
        print "User not available"

def keyeststep3():
    keyeststep3.Nb = bytes(random.getrandbits(32))
    aesgcm = AESGCM(temp["sk"])
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, keyeststep3.Nb, None)
    batch = {"ct": ct,
             "nonce": nonce}

    fillauthpacket(pkt1, "KEY_EST", 4, bytes(batch))
    sendpacket(pkt1.SerializeToString(), addr[0], addr[1])

def keyeststep4(rec):
    pack = pkt1.smsg.actMsg

    keyeststep4.Na = bytes(random.getrandbits(32))
    A = uname  # A's Username
    keyeststep4.B = rec  # Receiver's name from the list
    dict_to_serv = {"Na": keyeststep4.Na,
                    "A": A,
                    "B": keyeststep4.B,
                    "Baddr": addr,
                    "pack": pack}
    fillauthpacket(pkt1, "KEY_EST", 5,
                   bytes(base64.b64encode
                         (serverkeyencryption(public_key_loading("pubkey.der"), bytes(dict_to_serv)))))
    sendpacket(pkt1.SerializeToString(), SIP, UDP_PORT)

def keyeststep6():
    step6output = ast.literal_eval(pkt1.smsg.actMsg)
    noncefora = step6output["noncefora"]
    enc_packet = step6output["enc_packet"]

    aesgcm = AESGCM(temp["sk"])
    try:
        packet = ast.literal_eval(aesgcm.decrypt(noncefora, enc_packet, None))
        Sab = packet["Sab"]

        ticket_to_B = packet["ticket_to_B"]
        Baddr = packet["Baddr"]
        nticket = packet["nticket"]
        rNa = packet["Na"]
        if keyeststep4.Na == rNa and packet["B"] == keyeststep4.B:
            temp_known_users[packet["Baddr"]] = {"Sab": Sab,
                                                 "name": packet["B"]}
            keyeststep6.N1 = bytes(random.getrandbits(32))
            nonceforN1 = os.urandom(12)
            aesgcm = AESGCM(Sab)
            encN1 = aesgcm.encrypt(nonceforN1, keyeststep6.N1, None)

            step7output = {"encN1": encN1,
                           "nonceforN1": nonceforN1,
                           "ticket_to_B": ticket_to_B,
                           "nticket": nticket}
            fillauthpacket(pkt1, "KEY_EST", 7, bytes(step7output))
            sendpacket(pkt1.SerializeToString(), Baddr[0], Baddr[1])
        else:
            print "Server invalid"
    except cryptography.exceptions.InvalidTag:
        print "Decrypt not okay"

def keyeststep7():
    # Decrypt the ticket
    fetched = ast.literal_eval(pkt1.smsg.actMsg)
    Session_Key_B = temp["sk"]
    aesgcm = AESGCM(Session_Key_B)
    try:
        ticket = ast.literal_eval(aesgcm.decrypt(fetched["nticket"], fetched["ticket_to_B"], None))
        # Decrypt N1
        # check if the sender is actually the one who's name is in the ticket
        if ticket["Nb"] == keyeststep3.Nb and ticket["Aaddr"] == addr:
            temp_known_users[ticket["Aaddr"]] = {"Sab": ticket["Sab"],
                                                 "name": ticket["A"]}
            aesgcm = AESGCM(ticket["Sab"])
            try:
                N1 = aesgcm.decrypt(fetched["nonceforN1"], fetched["encN1"], None)
                # Calculate N1 - 1
                newN1 = int(N1) - 1
                keyeststep7.N2 = random.getrandbits(32)
                numbers = {"newN1": newN1,
                           "N2": keyeststep7.N2}
                noncefornumbers = os.urandom(12)
                encnumbers = aesgcm.encrypt(noncefornumbers, bytes(numbers), None)
                step8output = {"encnumbers": encnumbers,
                               "noncefornumbers": noncefornumbers}
                fillauthpacket(pkt1, "KEY_EST", 8, bytes(step8output))
                sendpacket(pkt1.SerializeToString(), addr[0], addr[1])
            except cryptography.exceptions.InvalidTag:
                print "Decrypt not okay"
        else:
            print "Ticket invalid"
            fillauthpacket(pkt1, "KEY_EST", 8, "Incorrect")
            sendpacket(pkt1.SerializeToString(), addr[0], addr[1])
    except cryptography.exceptions.InvalidTag:
        print "Decrypt not okay"

def keyeststep8():
    received = ast.literal_eval(pkt1.smsg.actMsg)
    # otheruser = temp_known_users[addr]["name"]
    Session_AB = temp_known_users[addr]["Sab"]
    aesgcm = AESGCM(Session_AB)
    try:
        numbers = ast.literal_eval(aesgcm.decrypt(received["noncefornumbers"], received["encnumbers"], None))
        # Verify the nonce returned
        if numbers["newN1"] == int(keyeststep6.N1) - 1:
            noncefordata = os.urandom(12)
            newN2 = int(numbers["N2"]) - 1
            keyeststep8.s_g = 2
            keyeststep8.s_p = int(random.getrandbits(32))
            keyeststep8.u1_prikey = int(random.getrandbits(32))
            u1_pubkey = pow(keyeststep8.s_g, keyeststep8.u1_prikey, keyeststep8.s_p)
            tobeenc = {"newn2": newN2,
                       "dhA": u1_pubkey}

            enc_data = aesgcm.encrypt(noncefordata, bytes(tobeenc), None)

            step9output = {"noncefordata": noncefordata,
                           "enc_data": enc_data,
                           "g": keyeststep8.s_g,
                           "p": keyeststep8.s_p}

            fillauthpacket(pkt1, "KEY_EST", 9, bytes(step9output))
            sendpacket(pkt1.SerializeToString(), addr[0], addr[1])
        else:
            print "Could not verify!"
    except cryptography.exceptions.InvalidTag:
        print "Decrypt not okay"

def keyeststep9():
    received = ast.literal_eval(pkt1.smsg.actMsg)
    Session_AB = temp_known_users[addr]["Sab"]
    aesgcm = AESGCM(Session_AB)
    try:
        data = ast.literal_eval(aesgcm.decrypt(received["noncefordata"], received["enc_data"], None))
        if int(data["newn2"]) == keyeststep7.N2 - 1:
            s_g = received["g"]
            s_p = received["p"]
            u1_pubkey = data["dhA"]
            u2_prikey = int(random.getrandbits(32))
            u2_pubkey = pow(s_g, u2_prikey, s_p)
            ssAB = pow(u1_pubkey, u2_prikey, s_p)
            # print "ssAB okay"
            # print ssAB

            backend = default_backend()
            salt = os.urandom(16)
            # derive
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2 ** 14,
                r=8,
                p=1,
                backend=backend)
            kAB = kdf.derive(bytes(ssAB))
            known_users[temp_known_users[addr]["name"]] = {"ssAB": kAB,
                                                           "addr": addr}
            # print known_users
            nonceforu2pubkey = os.urandom(12)
            enc_u2pubkey = aesgcm.encrypt(nonceforu2pubkey, bytes(u2_pubkey), None)
            step10output = {"nonceforu2pubkey": nonceforu2pubkey,
                            "enc_u2pubkey": enc_u2pubkey,
                            "salt": salt}
            fillauthpacket(pkt1, "KEY_EST", 10, bytes(step10output))
            sendpacket(pkt1.SerializeToString(), addr[0], addr[1])
        else:
            print "Client's key invalid"
    except cryptography.exceptions.InvalidTag:
        print "Decrypt not okay"

def keyeststep10():
    received = ast.literal_eval(pkt1.smsg.actMsg)
    salt = received["salt"]
    aesgcm = AESGCM(temp_known_users[addr]["Sab"])
    try:
        u2_pubkey = int(aesgcm.decrypt(received["nonceforu2pubkey"], received["enc_u2pubkey"], None))
        ssAB = pow(u2_pubkey, keyeststep8.u1_prikey, keyeststep8.s_p)

        backend = default_backend()
        # derive
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
            backend=backend)
        kAB = kdf.derive(bytes(ssAB))
        known_users[temp_known_users[addr]["name"]] = {"ssAB": kAB,
                                                       "addr": addr}
        aesgcm = AESGCM(kAB)
        nonceformsg = os.urandom(12)
        message = aesgcm.encrypt(nonceformsg, keyestfunction.smsg, None)
        msgtosend = {"nonceformsg": nonceformsg,
                     "msg": message}
        fillauthpacket(pkt1, "Data", 0, bytes(msgtosend))
        sendpacket(pkt1.SerializeToString(), addr[0], addr[1])
    except cryptography.exceptions.InvalidTag:
        print "Decrypt not okay"

def logout():
    logout.Nl = int(random.getrandbits(32))
    # print logout.Nl
    packet = {"uname": uname,
              "Nl": logout.Nl}
    nonce = os.urandom(12)
    aesgcm = AESGCM(temp["sk"])
    ct = aesgcm.encrypt(nonce, bytes(packet), None)

    logoutreq = {"ct": ct,
                 "nonce": nonce}
    fillauthpacket(pkt1, "LOGOUT", 1, bytes(logoutreq))
    sendpacket(pkt1.SerializeToString(), SIP, UDP_PORT)
    print "Logout request sent to server"

def logoutack():
    if pkt1.smsg.stepNumber == 2:
        packet = ast.literal_eval(pkt1.smsg.actMsg)
        nonce = packet["nonce"]
        ct = packet["ct"]
        aesgcm = AESGCM(temp["sk"])
        try:
            newNl = long(aesgcm.decrypt(nonce, ct, None))
            if newNl == logout.Nl + 1:
                return 1
            else:
                print "Someone else wants to log you out!"
                return 0
        except cryptography.exceptions.InvalidTag:
            print "Decrypt not okay"

# basic function
def chat():
    chat.message = raw_input('+>')

    # extracting the command
    cmd = chat.message.partition(' ')[0]

    if cmd == "list":
        getlist()

    elif cmd == "send":
        keyeststep1()

    elif cmd == "disconnect":
        # msg = chat.message[5:]
        # # extracting receiver's name
        rec = chat.message[11:]
        if rec in known_users:
            aesgcm = AESGCM(known_users[rec]["ssAB"])
            nonceforct = os.urandom(12)
            ct = aesgcm.encrypt(nonceforct, bytes("Bye"), None)
            dcdict = {"ct": ct,
                      "nonceforct": nonceforct}
            fillauthpacket(pkt1, "Data", 1, bytes(dcdict))
            daddr = known_users[rec]["addr"]
            sendpacket(pkt1.SerializeToString(), daddr[0], daddr[1])
            del temp_known_users[known_users[rec]["addr"]]
            del known_users[rec]
            print rec, "has been disconnected"

        else:
            print "You have no established connection with", rec

    elif cmd == "logout":
        logout()

def handledata():
    if pkt1.smsg.stepNumber == 0:
        sender = temp_known_users[addr]["name"]
        kAB = known_users[sender]["ssAB"]
        rcvdmsg = ast.literal_eval(pkt1.smsg.actMsg)
        aesgcm = AESGCM(kAB)
        try:
            rmsg = aesgcm.decrypt(rcvdmsg["nonceformsg"], rcvdmsg["msg"], None)
            print sender, ":", rmsg
        except cryptography.exceptions.InvalidTag:
            print "Decrypt not okay"
    elif pkt1.smsg.stepNumber == 1:
        rec = temp_known_users[addr]["name"]
        kAB = known_users[rec]["ssAB"]
        rcvdmsg = ast.literal_eval(pkt1.smsg.actMsg)
        aesgcm = AESGCM(kAB)
        try:
            rmsg = aesgcm.decrypt(rcvdmsg["nonceforct"], rcvdmsg["ct"], None)
            if rmsg == "Bye":
                del known_users[rec]
                del temp_known_users[addr]
                print rec, "terminated the session with you"
        except cryptography.exceptions.InvalidTag:
            print "Decrypt not okay"
    else:
        print "Invalid packet"

def receivepacket(sc):
    global r
    global rdata, addr
    while True:
        try:
            maxpkglen = 1024*1024
            sc.settimeout(30.0)
            rdata, addr = sc.recvfrom(maxpkglen)
            if rdata:
                pkt1.ParseFromString(rdata)
                if pkt1.msgType == "Login":
                    r = authfunction()

                elif pkt1.msgType == "KEY_EST":
                    keyestfunction()

                elif pkt1.msgType == "List":
                    pprint.pprint(recvlist())

                elif pkt1.msgType == "Data":
                    handledata()

                elif pkt1.msgType == "LOGOUT":
                    print "Press enter to logout"
                    if logoutack():
                        r = -2
                        break

                else:
                    print "Invalid packet received"

        except socket.error:
            print "Still receiving data"

def enthread(target):
    q = queue.Queue()

    def wrapper():
        q.put(target)

    t = threading.Thread(target=wrapper)
    t.start()
    return q

def authfunction():
    if pkt1.smsg.stepNumber == 2:
        receivechallengesendresponse(uname, pkt1)
        return 0

    elif pkt1.smsg.stepNumber == 4:
        if pkt1.smsg.actMsg == "unregistered":
            return -1
        elif pkt1.smsg.actMsg == "preregistered":
            return -1
        else:
            receivecontricalsessionkey(pswd, pkt1)
            return 0

    elif pkt1.smsg.stepNumber == 6:
        if pkt1.smsg.actMsg == "Incorrect":
            return -1
        else:
            return srplaststep(pkt1)

    else:
        print "Authentication Error"
        return 0

def sendfunction(rec, availusers):
    if rec in known_users:
        kAB = known_users[rec]["ssAB"]
        aesgcm = AESGCM(kAB)
        nonceformsg = os.urandom(12)
        message = aesgcm.encrypt(nonceformsg, keyestfunction.smsg, None)
        msgtosend = {"nonceformsg": nonceformsg,
                     "msg": message}
        fillauthpacket(pkt1, "Data", 0, bytes(msgtosend))
        sendpacket(pkt1.SerializeToString(), availusers[rec]["ipaddr"], availusers[rec]["port"])

    else:
        fillauthpacket(pkt1, "KEY_EST", 3, "Connect")
        sendpacket(pkt1.SerializeToString(), availusers[rec]["ipaddr"], availusers[rec]["port"])

def keyestfunction():
    if pkt1.smsg.stepNumber == 2:
        keyeststep2()

    elif pkt1.smsg.stepNumber == 3 and pkt1.smsg.actMsg == "Connect":
        # print "in 3"
        keyeststep3()

    elif pkt1.smsg.stepNumber == 4:
        keyeststep4(keyestfunction.rec)

    elif pkt1.smsg.stepNumber == 6:
        keyeststep6()
    elif pkt1.smsg.stepNumber == 7:
        keyeststep7()

    elif pkt1.smsg.stepNumber == 8:
        keyeststep8()

    elif pkt1.smsg.stepNumber == 9:
        keyeststep9()

    elif pkt1.smsg.stepNumber == 10:
        keyeststep10()

    else:
        print "else for KeyEst"


# socket creation
if __name__ == "__main__":
    try:
        sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error, msg:
        print 'Socket creation failed', msg

    uname = raw_input('Username: ')
    pswd = raw_input('Password: ')
    sendloginrequest()

    rthread = threading.Thread(target=receivepacket, args=(sc,))
    rthread.daemon = True
    rthread.start()

    while True:
        if r == 1:
            chat()

        elif r == -1:
            print "Incorrect credentials were entered"
            sc.close()
            break

        elif r == -2:
            print "You have been logged out"
            sc.close()
            break