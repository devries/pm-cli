pm-cli
======

This is a command-line driven password manager. ...

Mode of Operation
-----------------
- Uses a master password to encrypt passwords and notes.
- Generates key with PDKDF2 with SHA256 hash.
- Uses first 128 bits of hash as a signature, and last 128 bits to do AES
  encryption.
- Uses Fernet standard for encryption/decryption with AES-128.
- Currently macOS only using pbcopy to place password in clipboard.

Instructions
------------
Coming soon...
