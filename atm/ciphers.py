# ATM-side crypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
import hashlib
from Crypto.Hash import SHA
from base64 import b64decode


# here we define AES functions


def generate_salt(length):
    # length is the length of the salt you want
    return get_random_bytes(length)


def pad(unpadded_message, pad_length):
    # unpadded_message is the message you want sent
    # pad_length is the length of the final message
    padded_message = unpadded_message + (((pad_length - len(unpadded_message)) % pad_length * '!'))
    return padded_message


# Creates new AES key
def create_aes_key():
    # this takes 32 random bytes to make our key
    new_key = get_random_bytes(32)
    return new_key


# Takes a message and AES key, and encrypts the message.
def encrypt_aes(message, key):
    # key has to be 16 bytes long, probably generated from create_aes_key()
    # message is just the message you want to send
    message = pad(message)
    global IV
    IV = get_random_bytes(16)
    encrypt_cipher = AES.new(key, AES.MODE_CBC, IV)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text


# Takes a message and AES key, and decrypts the message.
def decrypt_aes(message, key):
    # the key is the AES key that you generated earlier
    # message is the encrypted message you want to decrypt
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
    if type(message) is str:
        message = bytes(message, 'utf-8')
    # message is the message you want to send
    # pub_key is the public key that you got
    rsa_pub_cipher = PKCS1_OAEP.new(pub_key)
    encrypted_rsa = rsa_pub_cipher.encrypt(message)
    return encrypted_rsa


def export_public_key(key):
    # key is the public key object (RSA)
    return key.publickey().exportKey(format='DER')


# RSA decryption
# rsa_pub_cipher is the private key with padding
# decrypted_rsa is the decrypted ciphertext
# ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
def decrypt_rsa(encrypted_rsa, priv_key, isString=False):
    # applies RSA Padding
    # encrypted_rsa is the encrypted message
    # priv_key is the private key object
    rsa_priv_cipher = PKCS1_OAEP.new(priv_key)
    if isString:
        return rsa_priv_cipher.decrypt(encrypted_rsa).decode("utf-8")
    return rsa_priv_cipher.decrypt(encrypted_rsa)


# Applies a hash to message input
def hash_message(message):
    # message is anything you want hashes regardless of type.
    return(hashlib.sha3_256((str(message)).encode("utf-8")).hexdigest())


# Makes new RSA signature
def sign_data(key, data):
    data = data.encode("utf-8")
    signer = PKCS1_v1_5.new(key)
    digest = SHA.new()
    digest.update(b64decode(data))
    sign = signer.sign(digest)
    return sign


"""
plain_message = "fuck off"
plain_message = plain_message.encode("utf-8")
public_key = RSA.import_key("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJ4tb2LShx1pFYwcRGzA\ngn/2J7fowEuLY9vLMib9AokRwxbRQYmL2DKDTSq1B9TAot3ONmIFx88t9JwpdCYP\nfYqOFFo7LSffgzmwOdc1vPnLqGm/W2tavs2YJygSdmoy+s3hCrHq7IcXD/a7PR23\nv+88LkrnaZz9zsQlpuY1dJ7F5sAblf/u8rdPq6iu4LglSdNk9sC5jVSc5H5le8Gm\n2xbO+gyrS2YLpmzu32M9nvKenFFpLPig+zHFZYjoti5koseHINSAMaZc8QWHOMf+\nqtDPNI/EK76lUs7v3PZcN5QjglOc7j1TnR/tTD8olaRcA2lbxOAz3fJIjCCFWnaV\nNQIDAQAB\n-----END PUBLIC KEY-----")
encrypted_message = encrypt_rsa(message=plain_message, pub_key=public_key)
print(type(encrypted_message))
f = open("fuck.txt", "w")
f.write("%s" % (encrypted_message))
"""

'''
# Test Code for AES
message = "Hello, World"
key = create_aes_key()
encrypted = encrypt_aes(message, key)
print(encrypted)
decrypted = decrypt_aes(encrypted, key)
print(decrypted)
'''

# Test Code for default read/Write
def default_write():
    
