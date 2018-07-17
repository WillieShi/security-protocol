# this is where the code will go
from Crypto import Random
from Crypto.Cipher import AES
import base64

from Crypto.Cipher import AES
# Encryption
#encryption_suite = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
#cipher_text = encryption_suite.encrypt("A really secret message. Not for prying eyes.")

# Decryption
#decryption_suite = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
#plain_text = decryption_suite.decrypt(cipher_text)
encryption_key = "This is a key123"
plain_text_message = "A really secret message. Not for prying eyes."

def encrypt(message, key):
    encryption_suite = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    cipher_text = encryption_suite.encrypt(message)
    return cipher_text

def decrypt(message, key):
    ecryption_suite = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    plain_text = decryption_suite.decrypt(message)

encoded_text = encrypt(plain_text_message, encryption_key)

print(encoded_text)
