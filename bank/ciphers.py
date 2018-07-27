from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import secrets
import hashlib

# here we define initial variables
n_length = 32
our_message = "testing here please"


# here we define AES functions
def pad(unpadded_message):
    unpadded_message += (((32 - len(unpadded_message)) % 32 * '{'))
    return unpadded_message


def create_aes_key():
    # this takes 32 random bytes to make our key
    new_key = get_random_bytes(32)
    return new_key


def encrypt_aes(message, key):
    # key has to be 16 bytes long
    message = pad(message)
    global IV
    IV = get_random_bytes(16)
    encrypt_cipher = AES.new(key, AES.MODE_CBC, IV)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text


def decrypt_aes(message, key):
    decrypt_cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    # the decode thing stops the result from being b'decrypted_message'
    plain_text = decrypt_cipher.decrypt(message).decode("utf-8")
    return plain_text


# here we define RSA functions
def generate_prime_number():
    generated_number = number.getPrime(n_length)
    return generated_number

# not sure if these imports are more or less correct than the ones above for RSA.
# What version should we use for RSA..?


# generates rsa key
def generate_key():
    # using generate() to generate key
    # first parameter can be any number that is a multiple of 256 and greater than 1024
    # random = Crypto.Random.new()
    private = RSA.generate(2048)
    public = private.publickey()
    return private, public


# rsa encryption
def encrypt_rsa(message, pub_key):
    # applies RSA Padding
    rsa_pub_cipher = PKCS1_OAEP.new(pub_key)
    encrypted_rsa = rsa_pub_cipher.encrypt(message)
    return encrypted_rsa
    '''
    byte_msg = message.encode()
    encrypted_rsa = pub_key.encrypt(byte_msg, Random.new())
    return encrypted_rsa
    '''

# rsa decryption


def decrypt_rsa(encrypted_rsa, priv_key):
    # applies RSA Padding
    rsa_priv_cipher = PKCS1_OAEP.new(priv_key)
    decrypted_rsa = rsa_priv_cipher.decrypt(encrypted_rsa).decode("utf-8")
    return decrypted_rsa
    decrypted_rsa = priv_key.decrypt(encrypted_rsa).decode("utf-8")
    return decrypted_rsa


def hash_message(message):
    message = str(message)
    message = message.encode("utf-8")
    return(hashlib.sha3_256(message).hexdigest())


def diffie_hellman():
    modulus = generate_prime_number()
    base = generate_prime_number()
    return (modulus, base)


def sign_data(key, data):
    signer = PKCS1_OAEP.new(key)
    digest = SHA256.new()
    digest.update(b64decode(data))
    sign = signer.sign(digest)
    return b64encode(sign)


def diffie_bank():
    mod, base = diffie_hellman()
    #  insert write (mod, bas) to atm
    secret_number_b = secrets.randbelow(9999)
    side_bank = (bas**secret_number_b) % mod
    # insert write (side_bank) to atm
    # insert read (side_atm) from atm
    # final_bank is the final bank side key for diffie hellman
    final_bank = (side_atm**secret_number_a) % mod
    return final_bank

# any test code goes here


print(diffie_bank())
