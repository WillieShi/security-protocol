from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import os
import base64
import six

#here we define initial variables
n_length = 128
IV = 16 * '\x00'

#here we define AES functions
def create_aes_key():
    #this takes 16 random bytes to make our key
    new_key = get_random_bytes(32)
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

#here we define RSA functions
def generate_rsa_keys():
    secret_code = "Unguessable"
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8)
    file_out = open("rsa_key.bin", "wb")
    file_out.write(encrypted_key)
    print(key.publickey().exportKey())
#any test code goes here
generate_rsa_keys()
