import asyncio
import pickle
from base64 import b64encode

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from Message import Message


class Server:
    def __init__(self, private_key_path):
        self.private_key_path = private_key_path
        self.conns = {}

    def decrypt_session_key(self, ciphertext):
        private_key = RSA.import_key(open(self.private_key_path).read())
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(ciphertext)

    async def broadcast(self, source_addr, message):
        print(f"Broadcasting {source_addr}: {message}")
        for socket, conn in self.conns.items():
            if (socket != source_addr):
                # Encrypt message with this connection's session key
                payload = Message.encrypt(f"{source_addr}: {message}", conn['session_key'])
                pickled = pickle.dumps(payload)
                conn['writer'].write(pickled)
                await conn['writer'].drain()

    async def handle_new_conn(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"New connection from {addr}")

        # Clients send the session key immediately after connecting
        encrypted_session_key = await reader.read(1024)
        print("Encrypted session key: " + b64encode(encrypted_session_key).decode('utf-8'))
        decrypted_session_key = self.decrypt_session_key(encrypted_session_key)
        print("Decrypted session key: " + b64encode(decrypted_session_key).decode('utf-8'))
        writer.write("ACK".encode('utf-8'))
        await writer.drain()

        # Add new connection info to connections dictionary
        self.conns[addr] = {'writer': writer, 'session_key': decrypted_session_key}

        while True:
            data = await reader.read(1024)
            message = data.decode('utf-8')
            await self.broadcast(addr, message)

    async def start(self):
        server = await asyncio.start_server(
            self.handle_new_conn, '127.0.0.1', 8888)

        addr = server.sockets[0].getsockname()
        print(f'Serving on {addr}')

        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(Server("private.pem").start())