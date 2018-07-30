# ATM-side crypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
import hashlib
from Crypto.Hash import SHA1
from Crypto.Util import number
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from base64 import standard_b64encode, b64decode
from binascii import a2b_base64
from os.path import basename, exists
from xml.dom import minidom
import argparse


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
    # message is the message you want to send
    # pub_key is the public key that you got
    rsa_pub_cipher = PKCS1_OAEP.new(pub_key)
    encrypted_rsa = rsa_pub_cipher.encrypt(message)
    return encrypted_rsa


def export_public_key(key):
    # key is the public key object
    return key.publickey().exportKey(format='DER')

# RSA decryption
# rsa_pub_cipher is the private key with padding
# decrypted_rsa is the decrypted ciphertext
# ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
def decrypt_rsa(encrypted_rsa, priv_key):
    # applies RSA Padding
    # encrypted_rsa is the encrypted message
    # priv_key is the private key object
    rsa_priv_cipher = PKCS1_OAEP.new(priv_key)
    decrypted_rsa = rsa_priv_cipher.decrypt(encrypted_rsa).decode("utf-8")
    return decrypted_rsa


# Applies a hash to message input
def hash_message(message):
    # message is anything you want hashes regardless of type.
    return(hashlib.sha3_256((str(message)).encode("utf-8")).hexdigest())


# Makes new RSA signature
def sign_data(key, data):
    data = data.encode("utf-8")
    signer = PKCS1_v1_5.new(key)
    digest = SHA1.new()
    digest.update(b64decode(data))
    sign = signer.sign(digest)
    return sign
"""
def privKeyXML(pemPrivateKeyFile):
   with open (pemPrivateKeyFile, 'rb') as pkFile:
      pemPrivKey = pkFile.read()
   print(pemPrivKey)
   lines = pemPrivKey
   lines = lines
   lines = lines.replace(" ", '').split()
   print(lines)
   keyDer = DerSequence()
   keyDer.decode(a2b_base64(''.join(lines[1:-1])))
   xml  = '<RSAKeyValue>'
   xml += '<Modulus>'
   xml += standard_b64encode(number.long_to_bytes(keyDer[1]))
   xml += '</Modulus>'
   xml += '<Exponent>'
   xml += standard_b64encode(number.long_to_bytes(keyDer[2]))
   xml += '</Exponent>'
   xml += '<D>'
   xml += standard_b64encode(number.long_to_bytes(keyDer[3]))
   xml += '</D>'
   xml += '<P>'
   xml += standard_b64encode(number.long_to_bytes(keyDer[4]))
   xml += '</P>'
   xml += '<Q>'
   xml += standard_b64encode(number.long_to_bytes(keyDer[5]))
   xml += '</Q>'
   xml += '<DP>'
   xml += standard_b64encode(number.long_to_bytes(keyDer[6]))
   xml += '</DP>'
   xml += '<DQ>'
   xml += standard_b64encode(number.long_to_bytes(keyDer[7]))
   xml += '</DQ>'
   xml += '<InverseQ>'
   xml += standard_b64encode(number.long_to_bytes(keyDer[8]))
   xml += '</InverseQ>'
   xml += '</RSAKeyValue>'
   fileName = basename(pemPrivateKeyFile)
   with open (fileName+'.xml', 'w') as pkFile:
      pkFile.write(xml)
   return
#
# Get Long Int
#
def GetLong(nodelist):
   rc = []
   for node in nodelist:
      if node.nodeType == node.TEXT_NODE:
         rc.append(node.data)
   string = ''.join(rc)
   return number.bytes_to_long(b64decode(string))

# any test code goes here
privatekey, publickey = generate_key()
exported_priv = (privatekey.exportKey())
exported_priv = exported_priv.decode("utf-8")
exported_priv = exported_priv.replace("\n","")
exported_priv = exported_priv.encode("utf-8")
f= open("heck.txt","w+")
f.write("%s"% (exported_priv))
f.close()
privKeyXML("heck.txt")
"""
