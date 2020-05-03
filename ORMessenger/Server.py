from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import socket


class Server:
    def __init__(self, private_key_path):
        self.private_key_path = private_key_path

    def decrypt_session_key(self, ciphertext):
        private_key = RSA.import_key(open(self.private_key_path).read())
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(ciphertext)

    # server
    def or_server(self):
        host = '127.0.0.1'  # localhost
        port = 1234
        MAX_SIZE = 1024  # maximum size of message

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # initialize server socket
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # avoids "port in use" issue
        server_socket.bind((host, port))
        server_socket.listen()

        # client connection
        print("Waiting for client...")
        conn, addr = server_socket.accept()
        conn.send("User Connected. Waiting for server...".encode())
        print(addr, "connected, chat started.")

        # message handling
        while True:
            message = input(">>").encode()
            conn.send(message)
            print("message sent, wait for response")
            print("Received: ", conn.recv(MAX_SIZE).decode())