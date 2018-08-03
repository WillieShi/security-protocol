# ATM-side crypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random
import string

# here we define AES functions


def generate_salt(length):
    # length is the length of the salt you want
    # returns an encoded string of the specified length

    result = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(length))

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
    # key has to be a multiple of 16 bytes long, probably generated from create_aes_key()
    # message is just the message you want to send
    # the IV is the IV, shocking
    message = pad(message)
    encrypt_cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, IV)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text


# Takes a message and AES key, and decrypts the message.
def decrypt_aes(message, key, IV):
<<<<<<< HEAD
    # the key is the AES key
=======
    # the key is the AES key that was generated earlier
>>>>>>> e709fd7878cc0d41e75187f079ad062dacaa4327
    # message is the encrypted message you want to decrypt
    # the IV is still the IV
    decrypt_cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, IV)
    # ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
    plain_text = decrypt_cipher.decrypt(message).decode("utf-8")
    return plain_text


# Applies a hash to message input
def hash_message(message):
    # message is anything you want hashed regardless of type.
    return(hashlib.sha256((str(message)).encode("utf-8")).hexdigest())
