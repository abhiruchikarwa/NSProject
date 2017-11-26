import socket
import sys
import os
import pickle

IP_ADDR = '0.0.0.0'
UDP_PORT = 9090

# creating a socket
# parameters: domain, type, protocol(optional)
# domain here is IP(AF_INET), can be IPv6(AF_INET6)
# type is SOCK_DGRAM(user datagram protocol)

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