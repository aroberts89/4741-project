from base64 import b64encode

from Client import Client
from Message import Message
from Server import Server

# Client generates a random session key on construction
client = Client("receiver.pem")
server = Server("private.pem")

# Client encrypts its session key with the server's public key
encrypted_session_key = client.encrypt_session_key()

# Server decrypts the session key sent to it using its private key
decrypted_session_key = server.decrypt_session_key(encrypted_session_key)

# This session key is then used to encrypt/decrypt messages in either direction
message = "Hi there"
print("Original message: " + message)

nonce, ciphertext, tag = Message.encrypt(message, decrypted_session_key)
print("Ciphertext: " + b64encode(ciphertext).decode('utf-8'))

print("Decrypted message: " + Message.decrypt(nonce, ciphertext, tag, decrypted_session_key))
