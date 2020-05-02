from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


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
