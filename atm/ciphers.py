# ATM-side crypto
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hashlib
import os

# here we define AES functions


def generate_salt(length):
    # length is the length of the salt you want
    # returns an encoded string of the specified length

    result = os.urandom(length)
    return result.encode('utf-8')


def generate_byte_length_num(length):
    # returns hex encoded message of the specified length
    return int(generate_salt(length).encode('hex'), 16)


def num_to_string(num):
    return hex(num).decode('hex')


def pad(unpadded_message):
    # unpadded_message is the message you want sent
    # pads the message until the length is a multiple of 16
    # it prepends 0's to the message
    while len(unpadded_message) % 16 != 0:
        unpadded_message = "0" + unpadded_message
    return unpadded_message


# Creates new AES key
def create_aes_key():
    # this takes 32 random bytes to make our key
    new_key = generate_salt(32)
    return new_key


# Takes a message and AES key, and encrypts the message.
def encrypt_aes(message, key, IV):
    return message
    # key has to be a multiple of 16 bytes long, probably generated from create_aes_key()
    # message is just the message you want to send
    # the IV is the IV, shocking
    message = pad(message)
    ctr = Counter.new(128, initial_value=hex_to_num(IV))
    encrypt_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text


# Takes a message and AES key, and decrypts the message.
def decrypt_aes(message, key, IV):
    return message
    # the key is the AES key
    # the key is the AES key that was generated earlier
    # message is the encrypted message you want to decrypt
    ctr = Counter.new(128, initial_value=hex_to_num(IV))
    decrypt_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    # ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
    plain_text = decrypt_cipher.decrypt(message).decode("utf-8")
    return plain_text


def hex_to_num(string):
    return int(''.join(format(ord(x), 'b') for x in string), 2)


# Applies a hash to message input
def hash_message(message):
    # message is anything you want hashed regardless of type.
    return(hashlib.sha256((str(message)).encode("utf-8")).hexdigest())
