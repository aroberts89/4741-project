from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class Server:
    def __init__(self, private_key_path):
        self.private_key_path = private_key_path

    def decrypt_session_key(self, ciphertext):
        private_key = RSA.import_key(open(self.private_key_path).read())
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(ciphertext)
