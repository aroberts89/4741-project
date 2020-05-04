import asyncio
import pickle
from base64 import b64encode

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from aioconsole import ainput

from Message import Message


class Client:
    def __init__(self, server_host, server_port, public_key_path):
        self.session_key = get_random_bytes(32)
        self.public_key_path = public_key_path
        self.server_host = server_host
        self.server_port = server_port

    # Returns this instance's session key, encrypted with the server's public key
    def encrypt_session_key(self):
        recipient_key = RSA.import_key(open(self.public_key_path).read())
        # "PKCS#1 OAEP is an asymmetric cipher based on RSA and the OAEP padding"
        # (see https://www.pycryptodome.org/en/latest/src/cipher/oaep.html)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return cipher_rsa.encrypt(self.session_key)

    async def receive_message_loop(self):
        while True:
            pickled = await self.reader.read(1024)
            nonce, ciphertext, tag = pickle.loads(pickled)
            message = Message.decrypt(nonce, ciphertext, tag, self.session_key)
            print(message)

    async def send_message_loop(self):
        while True:
            message = await ainput()
            payload = Message.encrypt(message, self.session_key)
            pickled = pickle.dumps(payload)
            self.writer.write(pickled)
            await self.writer.drain()

    async def start(self):
        reader, writer = await asyncio.open_connection(
            '127.0.0.1', 8888)
        self.reader = reader
        self.writer = writer
        # First, create and send our session key
        print(f"DEMO: Session key: {b64encode(self.session_key).decode('utf-8')}")
        encrypted_session_key = self.encrypt_session_key()
        print(f"DEMO: Encrypted session key: {b64encode(encrypted_session_key).decode('utf-8')}")
        self.writer.write(encrypted_session_key)
        await self.writer.drain()
        # Wait for server's acknowledgement
        await self.reader.read(1024)
        asyncio.create_task(self.receive_message_loop())
        await asyncio.create_task(self.send_message_loop())

if __name__ == "__main__":
    asyncio.run(Client("127.0.0.1", 8888, "receiver.pem").start())
