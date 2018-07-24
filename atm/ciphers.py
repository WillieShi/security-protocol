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
    #changing message into bytes
    byte_msg = message.encode()
    encrypted_rsa = pub_key.encrypt(byte_msg, Random.new())
    return encrypted_rsa

#rsa decryption
def decrypt_rsa(cipher_rsa, priv_key):
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
#secret1,secret2 = deffie_hellman()
#print("Alice's secret: ", secret1)
#print("Bob secret: ", secret2)
#print(generate_prime_number)

print(len(encrypt_rsa(encrypt_rsa("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", bytes("MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB31DDrnoN3seobaoNkeUk+OhvqSH89ZBcSG93ZuICWg7xf1Go2uDI1+/YQ83vOEs9eGSRcvgFdWMDo+w59hTGvrcb789PdT49lkR1oTX6ympSVa1+ylCnssCxVveTEfcygwXA2UVAkrNdlkNJ/Lav2w/ZO/Dl//e8pNT6Y0XZ5R20+VLBBvXwoHh7sQRxMqmZpKOaFwIZECCIQp7BlJxfXKvEGdypb0+X/CDNAAqP4T3sqTudMbhB2uj/cfo1hcr4Vi4Z0CbaiUl9XF2Sa+LFgeABa4I+ktHCzNnew+v74MUJxhacGW19PJJSN4ZZU4YD+/QVPKn087os9SRRGZAQpAgMBAAE=")), bytes("MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBQ36WCXmJqyA8pbI7W4cVjlpvjSU5fOLAq7/wQBVogeIwBvCGH6gMltwHWkclPNNOzGN4DWiGwQn3w1u6CBFyy9U+br12gPEyE6g2S9t3tCHCkTjfzaFIPZKY5PbDXziTRlMZxZzbPhd12e4vzXQTfnCdPaG8etwPIyUflgeWo1QHFdMNNRINZdZQ7K6EUs86ucazVQpMBNh4sLrRaZacsEWqdiLYsUx8tfV6QhQMSLim4qgaLXGUrPQ07c+ewmjiCL0S75eC0cMy4Sdl0InG/VpMbgO73uUxTDrZFCLop2FJzSh1MvE9Ir6a3y1XHRVPkpojS/k1ehsFhUeUB00k5AgMBAAE="))))
