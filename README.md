*This system was developed as part of the coursework of the Network Security course taken in the Master of Science in Computer Science program at Northeastern University, Boston, MA.*


To get the server running, run server.py. The file takes no command line arguments.
If you want to change the IP address and the port that you want to bind the server to, update those values in sconf.json.
The server keeps track of all the registered users by storing their names and password hashes is the users.json file. This file is only accessible to the server and isn't encrypted.
We kept the sconf.json and users.json separate to avoid having a single point of failure.

If you want to login as a user, run the client.py file. The file takes no command line arguments and when run on a terminal, it prompts the user for their user name and password, immediately on startup. The user name and passwords can be either of these pairs:

Alice: P4nc@ke$
Bob: i<3j@1eb!
Chris: pizza
Dana: QMpg864^%al%#wj@j
Eric: password

Our system only allows these preregistered users to join the IMS.

If you change the IP address or the port of the server, make sure that these changes are reflected in the config.json file too, as it is the configuration file meant for the clients.

The client also has access to the server's public key whose path is stored in the config.json file.
The server can access its private key in the same way. The path of the private key is stored in the sconf.json file.

If you change either of those files, let those changes be taken care of in both of the configuration files.

Our design model is such that the server is trusted and acts as a KDC. If the server is malicious during the key establishment phase, the symmetric key that the clients use for encrypting their conversation is compromised.

The server generates a session key with every user and stores this key until the user logs out, in which case both user and the server forget the established session key. If the server is compromised and the attacker can obtain this session key, as the server stores it temporarily till the user is in a logged in session.