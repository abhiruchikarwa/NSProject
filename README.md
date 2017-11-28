# NetSecProject

This project intends to build a chat application for multiple clients with a primary focus on integrity, confidentiality and authenticity of the messages exchanged.

The secure instant messaging system will have one server and multiple clients.
A client application can have multiple users where a user log in after another has finished their session and has logged out.

All the users are pre-registered with the server. 
Every user will have a username and a password which will be used for logging into the system; only the user knows his/her password.
The username-password pair will be stored on the server, but in a secured manner.
Every client in the system will know the public key amongst the public-private key pair of the server.
No other keys or passwords are stored