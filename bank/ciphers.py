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
    ctr = Counter.new(128, init_val=IV)
    encrypt_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    cipher_text = encrypt_cipher.encrypt(message)
    return cipher_text


# Takes a message and AES key, and decrypts the message.
def decrypt_aes(message, key, IV):
    # the key is the AES key that you generated earlier
    # message is the encrypted message you want to decrypt
    ctr = Counter.new(128, init_val=IV)
    decrypt_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    # ".decode("utf-8")" omits the "b" at the beginning of the decoded plaintext
    plain_text = decrypt_cipher.decrypt(message).decode("utf-8")
    return plain_text


<<<<<<< HEAD
=======
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
    #if type(message) is str:
        #message = str.encode(message)
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


>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
# Applies a hash to message input
def hash_message(message):
    # message is anything you want hashes regardless of type.
    return(hashlib.sha3_256((str(message)).encode("utf-8")).hexdigest())
<<<<<<< HEAD
=======


# Makes new RSA signature
def sign_data(key, data):
    signer = PKCS1_OAEP.new(key)
    digest = hashlib.sha1()
    digest.update(b64decode(data))
    sign = signer.sign(digest)
    return b64encode(sign)

# any test code goes here
"""
private, public = generate_key()
our_data = sign_data(private, "yo help plz")
print(our_data)
"""

#TESTING code
#rsa
'''
mess= "12345678"
pub ="b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJ4tb2LShx1pFYwcRGzA\ngn/2J7fowEuLY9vLMib9AokRwxbRQYmL2DKDTSq1B9TAot3ONmIFx88t9JwpdCYP\nfYqOFFo7LSffgzmwOdc1vPnLqGm/W2tavs2YJygSdmoy+s3hCrHq7IcXD/a7PR23\nv+88LkrnaZz9zsQlpuY1dJ7F5sAblf/u8rdPq6iu4LglSdNk9sC5jVSc5H5le8Gm\n2xbO+gyrS2YLpmzu32M9nvKenFFpLPig+zHFZYjoti5koseHINSAMaZc8QWHOMf+\nqtDPNI/EK76lUs7v3PZcN5QjglOc7j1TnR/tTD8olaRcA2lbxOAz3fJIjCCFWnaV\nNQIDAQAB\n-----END PUBLIC KEY-----'"
priv = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAqJ4tb2LShx1pFYwcRGzAgn/2J7fowEuLY9vLMib9AokRwxbR\nQYmL2DKDTSq1B9TAot3ONmIFx88t9JwpdCYPfYqOFFo7LSffgzmwOdc1vPnLqGm/\nW2tavs2YJygSdmoy+s3hCrHq7IcXD/a7PR23v+88LkrnaZz9zsQlpuY1dJ7F5sAb\nlf/u8rdPq6iu4LglSdNk9sC5jVSc5H5le8Gm2xbO+gyrS2YLpmzu32M9nvKenFFp\nLPig+zHFZYjoti5koseHINSAMaZc8QWHOMf+qtDPNI/EK76lUs7v3PZcN5QjglOc\n7j1TnR/tTD8olaRcA2lbxOAz3fJIjCCFWnaVNQIDAQABAoIBACNhzbbpzbN8gGh9\nFhFloJ/Bqi17ceOn9n/lxyWm+MBncsq1JwPRkP602sh+ha42/pUuZe8TcpMS7lm9\nyxUMR4PYZyfuJyy6iTRIDqqUdjpJUGruhbDxPgF7ssnEptsiPcBTIz3TR7CKSFSZ\nOYEBk2U7Fi3Amf6XasrQbfYvqFfoAeWSw8ho/h67S2dL8C2TBmLTZlT8t/n7uR9L\ntafvPJ4HqeRkq/ofiRInbU9gzt1teztm9yCjXYsTAU/toOf30oxJ4l/RX4yFM0gQ\nxIMcYXOytFH4lA8WRJk5rUaJoU3kbIraZMR69X7ti/maPN1YyaOak70LFbILctPQ\nVAHB2qECgYEAxmgL2q0OvB5DAXUhhzHo9Qo742cBG13OJJmkyNpwTV/s3HwgLaxB\nlxs6/uIE+uFeoIhORQJL2Z4ux58L3MJqrHiaO2Z75AvJLxHKU031giXdqm0wE+VG\nGGGGplgtp6WMIY//DMC3ohUZIrf/Umphfo/I4N71z2espxjWPBt7TAcCgYEA2ZB8\n+kLNohTDWCSFOpFpZlkGSKpZXSFPAy6dDn0v5+cz7TQ7thYRL0NBb32gamMZtror\nmfkJcXadylePWUnUM/4pctz5wd1mCzlBOTTSGoao1JId5qOBRLlRsoGHLoxD+oON\nAyr+4XMe3Omdr+c/KSwQocY3e+V/LGj0qIS3veMCgYEAw++irU00fQDhqUHUX6Ah\ncESwCg4CINWNq8Vz38shFriBwOhwGsq/Z4vDwkzRIDWK7rxNl4cCAyJdDlR6MYRq\nNnNP1ROLjBU7lFlcVtJpfyMH+rOjxDIq/A7sG8B/Lc2mSsra1OxJLS7qyMeuxOQ7\n7fHvLmvhkvbOoaI8h9WX+OcCgYBGccZFsgOrC1YE4C5TPGoIPaMPPDkbMoHG4fzw\niBBO4kmp8FO1LYf66afyVZbvW48j3zvm6v/nwSRuM9OycXlILG93RZ2I7Aryb2Nz\nBmtRM3DPA1CzMRXWDrspNU9z/u6z2ox6Dh3hGclQdkQchJ+q0R3Bg9DLSQ/YbVNq\njS6BSQKBgQCa2lDaet0cSgDd7edq6obbKMBXFI/6A8BeXanr0HIZfA5S7gEeryWi\nKbeqsLcQI8nduac7KNVo+DwNwQ9sDdbiCLyQ2f67wkdmcXa5/lSifjCVMHqTMiJY\nm1eXzqAiIGjxJUuoYUrn0WwzMo8PtZoVwzwuxUUBm3LT1aTbP3RaHA==\n-----END RSA PRIVATE KEY-----'

encrypt_msg = encrypt_rsa(mess, pub)
print("ENCRYPT:  ", encrypt_msg)
print("DECRYPT: ", decrypt_rsa(encrypt_msg, priv))
'''
>>>>>>> 65adf47bbe2cd2edacf9ac506417df4e8766dfab
