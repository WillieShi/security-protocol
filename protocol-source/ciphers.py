from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA
from Crypto.Util import number
import os
import base64
import six

#here we define variables
n_length = 256
prime_number_1 = 0
prime_number_2 = 0

#both the key and the message must be a multiple of 16 in length"

def encrypt_message_AES(message, key):
    #don't know what this line does. the var key is passed as an argument
    encryption_suite = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    #cipher_text is the encrypted code
    cipher_text = encryption_suite.encrypt(message)
    return cipher_text

def decrypt_message_AES(message, key):
    #still got no clue. key is passed as an arg yet again
    decryption_suite = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    #plain_text is the decrypted message
    plain_text = decryption_suite.decrypt(message).decode('utf-8')
    return plain_text

#RSA begins here
def is_prime(a):
    x = True
    for i in (2, a):
            while x:
               if a%i == 0:
                   x = False
               else:
                   x = True
    if x:
        print("prime")
    else:
        print("not prime")

def generate_prime_numbers():
    prime_number = number.getPrime(n_length)
    return prime_number
