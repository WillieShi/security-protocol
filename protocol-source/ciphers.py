from cryptography.fernet import Fernet
import os
import base64
import six
import rsa

#here we define variables
n_length = 128
symmetric_key = Fernet.generate_key()
#here we define functions

#here we define fernet encryption and decryption
def encrypt_message_symmetric(message, key):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(message.encode("utf-8"))
    return encrypted_text

def decrypt_message_symmetric(message, key):
    cipher_suite = Fernet(key)
    return(cipher_suite.decrypt(message).decode("utf-8"))

#here we define RSA

#code goes here
create_rsa_keys()
send_through_rsa("testing my rsa")
decrypt_rsa(encrypted_box)
