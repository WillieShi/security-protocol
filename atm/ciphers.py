from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import number
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import os
import base64
import six

#here we define initial variables
n_length = 2048
IV = 16 * '\x00'
our_message = "testing here please"

#here we define AES functions
def pad(unpadded_message):
    unpadded_message += (((32 - len(unpadded_message)) % 32 * '{'))
    return unpadded_message

def create_aes_key():
    #this takes 32 random bytes to make our key
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
def generate_prime_number():
    generated_number = number.getPrime(n_length)
    return generated_number

#not sure if these imports are more or less correct than the ones above for RSA.
#What version should we use for RSA..?
from Crypto.Cipher import PKCS51_OAEP

#generates rsa key
def generate_key():
    #using generate() to generate key
        #first parameter can be any number that is a multiple of 256 and greater than 1024
    priv_key = RSA.generate(1016, Random.new(), e=65537)
    pub_key = priv_key.publickey()
    return priv_key, pub_key

#rsa encryption
def encrypt_rsa(message, pub_key):
    cipher_rsa = pub_key.pub_key.encrypt(self, message, Random.new())
    return cipher_rsa

#rsa decryption
def decrypt_rsa(cipher_rsa):
    if 0 < encrypted_rsa < self.n:
        decrypted_rsa = priv_key.decrypt(cipher_rsa)
        return decrypted_rsa
    else:
        print("Encrypted RSA is too large.")



#any test code goes here
prime_number = generate_prime_number()
print(prime_number)