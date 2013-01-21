SecureSVN
=========

University Java project: Secure SVN server. Will keep track of multiple repositories and versions of the same file.

Local security is provided by a system-wide password (in order to startup the server one must know the password to unlock its keystore).

Client-Server communication is secured via an initial Partially Signed Diffie-Hellman exchange (the client sends a challenge which the server must sign with its private key and send back to the client. This step should guarantee that the client is in fact connected to the server) followed by AES encryption.

Login is managed via LDAP.

File and communication integrity is verified via MACs.
