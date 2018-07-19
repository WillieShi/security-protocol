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
from Crypto.Cipher import PKCS1_OAEP
import base64

#generates rsa key
def generate_key():
    #using generate() to generate key
        #first parameter can be any number that is a multiple of 256 and greater than 1024
    #random = Crypto.Random.new()
    priv_key = RSA.generate(2048)
    pub_key = priv_key.publickey()
    return priv_key, pub_key

#rsa encryption
def encrypt_rsa(message, pub_key):
    #changing message into bytes
    byte_msg = message.encode()
    cipher_rsa = pub_key.encrypt(byte_msg, Random.new())
    return cipher_rsa

#rsa decryption
def decrypt_rsa(cipher_rsa):
    decrypted_rsa = priv_key.decrypt(cipher_rsa).decode("utf-8")
    return decrypted_rsa

def hash_message(message):
    salt = bcrypt.gensalt()
    message = str(message)
    salt = salt.decode("utf-8")
    message = message + salt
    message = message.encode("utf-8")
    return(hashlib.sha3_256(message).hexdigest())
#any test code goes here

priv_key, pub_key = generate_key()
print("Public key: ", pub_key)
print("Private key: ",priv_key)
message = encrypt_rsa("Testing", pub_key)
print("encrypted message: ", message)
print(decrypt_rsa(message))

#print(generate_prime_number)
