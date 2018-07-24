from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import number
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from random import randint
import os
import base64
import six
from Crypto.Cipher import PKCS1_OAEP

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
#private_key = private.exportKey(format='DER')
#public_key = private.publickey().exportKey(format='DER')

#generates rsa key
def generate_key():
    #using generate() to generate key
    #first parameter can be any number that is a multiple of 256 and greater than 1024
    #random = Crypto.Random.new()
    private = RSA.generate(2048)
    public = private.publickey()
    return private, public

#rsa encryption
def encrypt_rsa(message, pub_key):
    #applies RSA Padding
    rsa_pub_cipher = PKCS1_OAEP.new(pub_key)
    encrypted_rsa = rsa_pub_cipher.encrypt(message)
    return encrypted_rsa
    '''
    byte_msg = message.encode()
    encrypted_rsa = pub_key.encrypt(byte_msg, Random.new())
    return encrypted_rsa
    '''

#rsa decryption
def decrypt_rsa(encrypted_rsa, priv_key):
    #applies RSA Padding
    rsa_priv_cipher = PKCS1_OAEP.new(priv_key)
    decrypted_rsa = rsa_priv_cipher.decrypt(encrypted_rsa).decode("utf-8")
    return decrypted_rsa
    decrypted_rsa = priv_key.decrypt(encrypted_rsa).decode("utf-8")
    return decrypted_rsa

def hash_message(message):
    salt = bcrypt.gensalt()
    message = str(message)
    salt = salt.decode("utf-8")
    message = message + salt
    message = message.encode("utf-8")
    return(hashlib.sha3_256(message).hexdigest())

#deffie hellman key exchange
def deffie_atm(mod, bas):
    #insert read (mod, bas) from bank
    a = randint(1, 9999)
    side1 = (bas**a) % mod
    #insert read (side2) from bank
    #insert write (side1) to bank
    #final_a is the final atm side key for deffie hellman
    final_a = (side2**a) % mod
    return final_a

#any test code goes here
