from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import socket


class Client:
    def __init__(self, public_key_path):
        self.session_key = get_random_bytes(32)
        self.public_key_path = public_key_path

    # Returns this instance's session key, encrypted with the server's public key
    def encrypt_session_key(self):
        recipient_key = RSA.import_key(open(self.public_key_path).read())
        # "PKCS#1 OAEP is an asymmetric cipher based on RSA and the OAEP padding"
        # (see https://www.pycryptodome.org/en/latest/src/cipher/oaep.html)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return cipher_rsa.encrypt(self.session_key)

    # chat client
    def or_client(self):
        host = '127.0.0.1'
        port = 1234
        MAX_SIZE = 1024

        # connecting to server
        client_socket = socket.socket()
        client_socket.connect((host, port))

        # welcome message
        welcome = client_socket.recv(MAX_SIZE).decode()
        print(welcome)

        # message handling
        while True:
            print("Received: ", client_socket.recv(MAX_SIZE).decode())
            message = input(">>").encode()
            client_socket.send(message)
            print("message sent, wait for response")
