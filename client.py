import socket
import argparse
import pickle
import threading
import json
import packet_pb2


parser = argparse.ArgumentParser()
# username as input
# parser.add_argument('-u', type = str, help = 'input username', action = 'store')
# args = parser.parse_args()

with open('config.json') as json_data_file:
    data = json.load(json_data_file)

# print args

# values taken as input assigned to variables
# UN = args.u
SIP = data["ipaddr"]
UDP_PORT = data["port"]

# lists for storing data from the pickle file
names = []
addr = []
port = []

cl = []
cla = []
clp = []

ru = []
rip = []
rpn = []

####################################################
# Function to authenticate the server
# Changes made today by Ketan
def autheticatedLogin(uname, pwd):
    w = func(pwd);
    # send login request to the server
    pkt1 = packet_pb2.Packet()
    pkt1.msgType = "Login"
    pkt1.smsg.stepNumber = 1
    pkt1.smsg.actMsg = "This is my msg"

    sendmsg(pkt1.SerializeToString());

def  func(pwd):
    return pwd+"what"

####################################################
# function to send messages to another client
def sendmsg(smsg):
    # # removing the command from the original message
    # smsg = smsg[5:]
    # # extracting receiver's name
    # rec = smsg.partition(' ')[0]
    # # print rec
    # # to send data to the receiver
    # smsg = smsg[(len(rec) + 1):]
    # # print msg
    # getting the place of user item in 'names' list
    # i = names.index(rec)
    # # making variables for receiver's ip-address and port
    BUFFER_SIZE = 1024
    while smsg:
        sentbytes = sc.sendto(smsg[:BUFFER_SIZE], ("127.0.0.1", 9090))
        smsg = smsg[sentbytes:]


# function to receive messages from another client
def recvmsg():
    while True:
        # to receive data
        rdata, adr = sc.recvfrom(1024)
        try:
            with open('clients.pkl', 'rb') as f:
                while True:
                    ru.append(pickle.load(f))
                    rip.append(pickle.load(f))
                    rpn.append(pickle.load(f))
        except EOFError:
            pass
        if not rdata:
            chat()
        # extracting sender's username
        # we find the index of the given address in the list & extract the username
        j = rpn.index(adr[1])
        SUN = ru[j]
        print '<-- <From ' + str(adr[0]) + ' : ' + str(adr[1]) + ' : ' + SUN + '>: ' + rdata + '\n+>'


# basic function
def chat():
    while 1:
        # starting the message receiving thread
        rt = threading.Thread(target=recvmsg)
        rt.start()

        msg = raw_input('+>')

        # extracting the command
        cmd = msg.partition(' ')[0]

        if cmd == "list":
            try:
                with open('clients.pkl', 'rb') as f:
                    while True:
                        cl.append(pickle.load(f))
                        cla.append(pickle.load(f))
                        clp.append(pickle.load(f))
            except EOFError:
                pass
            print '<-- Signed In Users:' + ' '.join(str(p) for p in cl)
            cl[:] = []

        elif cmd == "send":
            try:
                with open('clients.pkl', 'rb') as f:
                    while True:
                        names.append(pickle.load(f))
                        addr.append(pickle.load(f))
                        port.append(pickle.load(f))
            except EOFError:
                pass

            try:
                # starting the message sending thread
                st = threading.Thread(target=sendmsg(msg))
                st.start()
                # sendmsg(msg)
            except socket.error as emsg:
                print 'Error: ' + str(emsg)

        else:
            print 'Incorrect command/message'


# socket creation
if __name__ == "__main__":
    try:
        sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sc.connect((SIP, UDP_PORT))
    except socket.error, msg:
        print 'Socket creation failed' + msg
    # calling the actual chat function to perform tasks
    autheticatedLogin("Ketan", "pwd")
    # closing connection
    sc.close
