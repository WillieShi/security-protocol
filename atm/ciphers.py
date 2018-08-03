# ATM-side crypto
# Fox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# from Crypto.PublicKey import RSA
# from Crypto.Signature import PKCS1_v1_5
# from Crypto.Cipher import PKCS1_OAEP
import hashlib


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
def encrypt_aes(message, key, IV):
    # key has to be 16 bytes long, probably generated from create_aes_key()
    # message is just the message you want to send
    message = pad(message)
    encrypt_cipher = AES.new(key, AES.MODE_CTR, IV)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text


# Takes a message and AES key, and decrypts the message.
def decrypt_aes(message, key, IV):
    # the key is the AES key that you generated earlier
    # message is the encrypted message you want to decrypt
    decrypt_cipher = AES.new(key, AES.MODE_CTR, IV)
    # ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
    plain_text = decrypt_cipher.decrypt(message).decode("utf-8")
    return plain_text


# Applies a hash to message input
def hash_message(message):
    # message is anything you want hashes regardless of type.
    return(hashlib.sha3_256((str(message)).encode("utf-8")).hexdigest())


'''
# Fox
# Makes new RSA signature
def sign_data(key, data):
    data = data.encode("utf-8")
    signer = PKCS1_v1_5.new(key)
    digest = SHA.new()
    digest.update(b64decode(data))
    sign = signer.sign(digest)
    return sign
'''

"""
bank_priv, bank_pub = generate_key()
f = open("bank_priv.pem", "wb")
priv_key = bank_priv.exportKey()
f.write("%s" % (priv_key))
f.close()
f = open("bank_priv.pem", "w")
f.write("\n")
f.write("%s" % (bank_priv.n))
f.write("\n")
f.write("%s" % (bank_priv.e))
f.write("\n")
f.write("%s" % (bank_priv.d))
f.write("\n")
f.write("%s" % (bank_priv.p))
f.write("\n")
f.write("%s" % (bank_priv.q))
f.write("\n")
f.write("%s" % (bank_priv.u))
f.write("\n")
f.close()

f = open("bank_pub.pem", "wb")
pub_key = bank_priv.publickey().exportKey()
f.write("%s" % (pub_key))
f.close()
f = open("bank_pub.pem", "w")
f.write("\n")
f.write("%s" % (bank_priv.n))
f.write("\n")
f.write("%s" % (bank_priv.e))
f.close()

bank_priv, bank_pub = generate_key()
f = open("card_priv.pem", "wb")
priv_key = bank_priv.exportKey()
f.close()
f = open("card_priv.pem", "w")
f.write("%s" % (priv_key))
f.write("\n")
f.write("%s" % (bank_priv.n))
f.write("\n")
f.write("%s" % (bank_priv.e))
f.write("\n")
f.write("%s" % (bank_priv.d))
f.write("\n")
f.write("%s" % (bank_priv.p))
f.write("\n")
f.write("%s" % (bank_priv.q))
f.write("\n")
f.write("%s" % (bank_priv.u))
f.write("\n")
f.close()

f = open("card_pub.pem", "wb")
priv_key = bank_priv.publickey().exportKey()
f.close()
f = open("card_pub.pem", "w")
f.write("%s" % (priv_key))
f.write("\n")
f.write("%s" % (bank_priv.n))
f.write("\n")
f.write("%s" % (bank_priv.e))
f.close()


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
