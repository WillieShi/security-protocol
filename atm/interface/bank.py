"""Backend of ATM interface for xmlrpc

Key for codes used in communication functions:
pvc = pin_verify()
pkv = private_key_verify()
ilw = inner_layer_write()
bbb = check_balance()
www = withdraw()

"""

import logging
import struct
import serial
import ciphers
from random import randint


class Bank:
    """Interface for communicating with the bank

    Args:
        port (serial.Serial): Port to connect to
    """

    def __init__(self, port, verbose=True):
        # self.ser = serial.Serial(port, baudrate=115200, timeout=2)
        self.verbose = verbose

    # Write function for when AES tunnel is not established.
    def default_write(self, msg):
        self.ser.write(msg)

    # Read function for when AES tunnel is not established.
    def default_read(self, size):
        return self.ser.read(size)

    # The ATM-side diffie hellman function, which receives the modulus and base from the bank.
    # Performs computations after receving modulus and base from bank.
    def diffie_atm(self):
        # Receives modulus and base from bank.
        transaction_id, mod, base = struct.unpack(">32s256s256s", self.default_read(544))
        # converts mod and base from bytes to int using process()
        mod = process(mod)
        base = process(base)
        # random.randint() is a pseudorandom num generator that returns a value N such that a <= N <= b
        secret_number_a = randint(0, 9999)
        side_atm = (base**secret_number_a) % mod
        # Receives bank's half of diffie hellman from bank to compute final value.
        transaction_id, side_bank = struct.unpack("32s256s", self.default_read(288))
        side_bank = process(side_bank)
        # Sends ATM's half of diffie hellman to bank.
        self.default_write(struct.pack("32s256s", format("dif_side_atm"), format(side_atm, 256)))
        # uptime_key_atm is the final ATM-side agreed value for diffie hellman
        # RECIEVE THE IV FROMT THE BANK
        # Fix
        self.bank_key, self.bank_IV = (side_bank**secret_number_a) % mod

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    # Sends to bank the card-encrypted balance (only card and bank have AES key), and the atm-encrypted balance (only atm and bank have AES key)
    def read_verify_or_withdraw(self):
        card_encrypted_balance, IV, atm_encrypted_balance = struct.pack(">16s16s16s", self.default_read(48))
        return card_encrypted_balance, IV, ciphers.decrypt_aes(atm_encrypted_balance, self.bank_key, self.bank_IV)

    # Encrypts information needed to verify user with atm-bank-only AES and sends to bank
    def write_verify(self, encrypted_hashed_passkey, card_id, pin):
        pkt = struct.pack(">32s32s16s", encrypted_hashed_passkey, ciphers.encrypt_aes(ciphers.hash_message(card_id+pin), self.bank_key, self.bank_IV), ciphers.encrypt_aes(card_id, self.bank_key, self.bank_IV))
        self.default_write(pkt)

    # Sends user's requested withdraw amount from atm to bank after encrypting
    def write_withdraw(self, withdraw_amount):
        pkt = struct.pack(">16s", ciphers.encrypt_aes(str(withdraw_amount), self.bank_key, self.bank_IV))
        self.default_write(pkt)
        return True

    # Begins provision process and sends important data to bank
    def provision_update(self, aes_key, IV, card_num, hashed_passkey, hashed_data):
        pkt = struct.pack(">32s16s16s32s32s", aes_key, IV, card_num, hashed_passkey, hashed_data)
        print(pkt)
        print(len(pkt))
        self.ser = serial.Serial('/dev/ttyO1', baudrate=115200, timeout=2)
        # total length is 128 bytes
        self.ser.write("p" + pkt)

        self._vp('Provisioning complete')

        return True

        self._vp('Provisioning complete')

    def stupid_provision_update(self):
        self.ser.write("f")


# Used to reformat inputs to bytes, which can then be packed using struct
def format(value, size=256):
    if type(value) is str:
        return value.encode("hex")
    else:
        return hex(value)


# Converts bytes back into int, only works on int
def process_to_string(value):
    return value.decode('hex')


def process_to_int(value):
    return int(value, 16)
