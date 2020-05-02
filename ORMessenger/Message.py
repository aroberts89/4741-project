from Crypto.Cipher import AES


class Message:
    @staticmethod
    def encrypt(message, key):
        """
        Encrypts a message using the provided session key.
        :param message: The message to encrypt
        :param key: The session key
        :return: A tuple of (nonce, ciphertext, tag)

        Some notes:
        * Calling AES.new without specifying a nonce makes it generate a random one
        * A nonce should not be used more than once with the same encryption key
        * EAX mode adds authenticity and integrity to standard AES
        """
        cipher_encrypt = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher_encrypt.encrypt_and_digest(message.encode('utf-8'))
        return (cipher_encrypt.nonce, ciphertext, tag)

    @staticmethod
    def decrypt(nonce, ciphertext, tag, key):
        """
        Decrypts a message using the provided session key.
        :param nonce: A unique value generated when this message was encrypted
        :param ciphertext: The encrypted message
        :param tag: The MAC tag generated when this message was encrypted
        :param key: The session key
        :return: The decrypted message
        """
        cipher_decrypt = AES.new(key, AES.MODE_EAX, nonce)
        return cipher_decrypt.decrypt_and_verify(ciphertext, tag).decode('utf-8')
