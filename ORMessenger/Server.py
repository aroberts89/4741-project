import asyncio

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


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
        for socket, writer in self.conns.items():
            if (socket != source_addr):
                writer.write(f"{source_addr}: {message}".encode('utf-8'))
                await writer.drain()

    async def handle_new_conn(self, reader, writer):
        # Add new connection to connections dictionary
        addr = writer.get_extra_info('peername')
        print(f"New connection from {addr}")
        self.conns[addr] = writer

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
    asyncio.run(Server("../private.pem").start())