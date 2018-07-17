from Crypto import Random
from Crypto.Cipher import AES
import base64

# Encryption
#encryption_suite = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
#cipher_text = encryption_suite.encrypt("A really secret message. Not for prying eyes.")

# Decryption
#decryption_suite = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
#plain_text = decryption_suite.decrypt(cipher_text)

#both the key and the message must be a multiple of 16 in length"
aes_key = "This is a key123"
plain_text_message = "aaaaaaaaaaaaaaaa"

def encrypt_message(message, key):
    #don't know what this line does. the var key is passed as an argument
    encryption_suite = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    #cipher_text is the encrypted code
    cipher_text = encryption_suite.encrypt(message)
    return cipher_text

def decrypt_message(message, key):
    #still got no clue. key is passed as an arg yet again
    decryption_suite = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    #plain_text is the decrypted message
    plain_text = decryption_suite.decrypt(message).decode('utf-8')
    return plain_text
