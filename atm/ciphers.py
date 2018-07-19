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

#decryption
def decrypt_rsa(encrypted_rsa):
    decrypted_rsa = decrypt(encrypted_rsa)
    return decrypted_rsa



#any test code goes here
prime_number = generate_prime_number()
print(prime_number)
