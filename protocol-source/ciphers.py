from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import base64
import six

#here we define variables
n_length = 128
IV = 16 * '\x00'

#here we define AES functions
def create_aes_key():
    #this takes 16 random bytes to make our key
    new_key = get_random_bytes(16)
    return new_key

def encrypt_aes(message, key):
    #key has to be 16 bytes long
    encrypt_cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text

def decrypt_aes(encrypted_message, key):
    decrypt_cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    #the decode thing stops the result from being b'decrypted_message'
    plain_text = decrypt_cipher.decrypt(encrypted_message).decode("utf-8")
    return plain_text
