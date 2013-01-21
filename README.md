SecureSVN
=========

University Java project: Secure SVN server. Will keep track of multiple repositories and versions of the same file.

Local security is provided by a system-wide password (in order to startup the server one must know the password to unlock its keystore).

Client-Server communication is secured via an initial Diffie-Hellman exchange followed by AES encryption.

Login is managed via LDAP.

File and communication integrity is verified via MACs.
