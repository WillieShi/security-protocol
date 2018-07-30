# Bank-side crypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from base64 import b64encode, b64decode
import hashlib


# here we define AES functions


def generate_salt(length):
    return get_random_bytes(length)

def pad(unpadded_message, pad_length):
    padded_message = unpadded_message + (((pad_length - len(unpadded_message)) % pad_length * '!'))
    return padded_message


# Creates new AES key
def create_aes_key():
    # this takes 32 random bytes to make our key
    new_key = get_random_bytes(32)
    return new_key


# Takes a message and AES key, and encrypts the message.
def encrypt_aes(message, key):
    # key has to be 16 bytes long
    message = pad(message)
    global IV
    IV = get_random_bytes(16)
    encrypt_cipher = AES.new(key, AES.MODE_CBC, IV)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text


# Takes a message and AES key, and decrypts the message.
def decrypt_aes(message, key):
    decrypt_cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    # ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
    plain_text = decrypt_cipher.decrypt(message).decode("utf-8")
    return plain_text


# generates rsa key
# using generate() to generate key
# first parameter can be any number that is a multiple of 256 and greater than 1024
def generate_key():
    private = RSA.generate(2048)
    public = private.publickey()
    return private, public


# RSA encryption
# rsa_pub_cipher is the public key with padding
# encrypted_rsa is the ciphertext
def encrypt_rsa(message, pub_key):
    # applies RSA Padding
    rsa_pub_cipher = PKCS1_OAEP.new(pub_key)
    encrypted_rsa = rsa_pub_cipher.encrypt(message)
    return encrypted_rsa

def export_public_key(key):
    return key.publickey().exportKey(format='DER')
# RSA decryption
# rsa_pub_cipher is the private key with padding
# decrypted_rsa is the decrypted ciphertext
# ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
def decrypt_rsa(encrypted_rsa, priv_key):
    # applies RSA Padding
    rsa_priv_cipher = PKCS1_OAEP.new(priv_key)
    decrypted_rsa = rsa_priv_cipher.decrypt(encrypted_rsa).decode("utf-8")
    return decrypted_rsa


# Applies a hash to message input
def hash_message(message):
    message = str(message)
    message = message.encode("utf-8")
    return(hashlib.sha3_256(message).hexdigest())


# Makes new RSA signature
def sign_data(key, data):
    signer = PKCS1_OAEP.new(key)
    digest = hashlib.sha1()
    digest.update(b64decode(data))
    sign = signer.sign(digest)
    return b64encode(sign)

# any test code goes here
