# Bank-side crypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib


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
