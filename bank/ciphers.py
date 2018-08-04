
# Bank-side crypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
from Crypto.Util import Counter


def generate_salt(length):
    # length is the length of the salt you want
    return get_random_bytes(length)


def pad(unpadded_message):
    # unpadded_message is the message you want sent
    # pad_length is the length of the final message
    while len(str(unpadded_message)) % 16 != 0:
        unpadded_message = "0" + str(unpadded_message)
    return unpadded_message


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
    ctr = Counter.new(128, initial_value=hex_to_num(IV))
    encrypt_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text


# Takes a message and AES key, and decrypts the message.
def decrypt_aes(message, key, IV):
    # the key is the AES key that you generated earlier
    # message is the encrypted message you want to decrypt
    ctr = Counter.new(128, initial_value=hex_to_num(IV))
    decrypt_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    # ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
    plain_text = decrypt_cipher.decrypt(message).decode("utf-8")
    return plain_text


# Applies a hash to message input
def hash_message(message):
    # message is anything you want hashes regardless of type.
    return(hashlib.sha256((str(message)).encode("utf-8")).hexdigest())


def hex_to_num(string):
    return int(''.join(format(ord(x), 'b') for x in string), 2)
