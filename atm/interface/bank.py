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
    uptime_key_atm = 0

    def __init__(self, port, verbose=False):
        self.ser = serial.Serial(port)
        self.verbose = verbose

    # Write function for when AES tunnel is not established.
    def default_write(self, msg):
        self.ser.write(msg)

    # Read function for when AES tunnel is not established.
    def default_read(self, size):
        return self.ser.read(size)

    # Sends AES encrypted message.
    def aes_write(self, msg):
        self.ser.write(ciphers.encrypt_aes(msg, self.uptime_key))

    # Receives and decrypts AES from message.
    def aes_read(self, size):
        return ciphers.decrypt_aes(self.ser.read(size), self.uptime_key)

    # The ATM-side diffie hellman function, which receives the modulus and base from the bank.
    # Performs computations after receving modulus and base from bank.
    def diffie_atm(self):
        # Receives modulus and base from bank.
        transaction_id, mod, base = struct.unpack(">32s256s256s", self.default_read(544))
        mod = process(mod)
        base = process(base)
        secret_number_a = randint(0, 9999)
        side_atm = (base**secret_number_a) % mod
        # Receives bank's half of diffie hellman from bank to compute final value.
        transaction_id, side_bank = struct.unpack("32s256s", self.default_read(288))
        side_bank = process(side_bank)
        # Sends ATM's half of diffie hellman to bank.
        self.default_write(struct.pack("32s256s", format("dif_side_atm"), format(side_atm, 256)))
        # uptime_key_atm is the final ATM-side agreed value for diffie hellman
        self.uptime_key_atm = (side_bank**secret_number_a) % mod
'''
    # Fox
    # Encrypts the verification number to test to see if the card is legitimate.
    def private_key_verify(self, card_id):
        self.aes_write("pkv" + struct.pack(">32s32s", format("private_key_verify"), format(card_id, 32)))
'''
    # Sends hashed card ID and PIN to the bank.
    def pin_verify(self, card_id, pin, passkey):
        transaction_id, card_id, pin, passkey = struct.unpack("32s32s32s16s", self.aes_read(112))
        val = "pvc" + struct.pack(">32s32s32s16s", format("pin_verify"), format(card_id, 32), format(ciphers.hash_message(card_id+pin), 32), format(passkey, 16))
        self.aes_write(val)

# IV = 16 byte number
'''
    # Fox
    # Decrypts the AES on the random number to send to the card.
    def private_key_verify_read(self):
        transaction_id, random_num, signature = struct.unpack(">32s256I256I", self.aes_read(544))
        random_num = process(random_num)
        signature = process(signature)
        return random_num, signature
'''
    # private_key_verify() sends the random_num the card decrypted back to bank
    def private_key_verify_write(self, random_num):
        val = "pkw" + struct.pack(">32s32s", format("private_key_verify_write"), format(random_num, 32))
        self.aes_write(val)
'''
    # Fox
    # Writes the inner onion layer to the bank.
    def inner_layer_write(self, inner_layer):
        val = "ilw" + struct.pack(">32s256s", format("send_inner_layer"), format(inner_layer, 256))
        self.aes_write(val)

    # Fox
    # Decrypts the AES on the onion from the bank to send to the card.
    def outer_layer_read(self):
        transaction_id, outer_layer, signature = struct.unpack(">32s512I256I", self.aes_read(800))
        outer_layer = process(outer_layer)
        signature = process(signature)
        return outer_layer, signature
'''
    # Encrypts the withdraw amount requested by the card to send to the bank.
    def withdraw_amount_write(self, amount):
        val = "waw" + struct.pack(">32s32s", format("send_withdraw_amount"), format(amount, 256))
        self.aes_write(val)

    # Sends a request to the bank to check the balance.
    def request_read_balance(self):
        val = "rrb" + struct.pack(">32s", format("request_read_balance"))
        self.aes_write(val)

    # Sends a request to the bank to reset the PIN.
    def pin_reset(self, pin):
        val = "pnr" + struct.pack(">32s32s", format("pin_reset"), format(pin, 32))
        self.aes_write(val)

    # Sends the balance to the card from the bank.
    def balance_read(self):
        transaction_id, balance = struct.unpack(">32s32I")
        balance = process(balance)
        return balance

    def reset(self):
        self.aes_write("rst")

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    def check_balance(self, atm_id, card_id):
        """Requests the balance of the account associated with the card_id

        Args:
            atm_id (str): UUID of the ATM
            card_id (str): UUID of the ATM card to look up

        Returns:
            str: Balance of account on success
            bool: False on failure
        """
        self._vp('check_balance: Sending request to Bank')
        pkt = "bbb" + struct.pack(">36s36s", atm_id, card_id)
        self.ser.write(pkt)

        while pkt not in "ONE":
            pkt = self.ser.read()

        if pkt != "O":
            return False
        pkt = self.ser.read(76)
        aid, cid, bal = struct.unpack(">36s36sI", pkt)

        self._vp('check_balance: returning balance')
        return bal

    def withdraw(self, atm_id, card_id, amount):
        """Requests a withdrawal from the account associated with the card_id

        Args:
            atm_id (str): UUID of the HSM
            card_id (str): UUID of the ATM card
            amount (str): Requested amount to withdraw

        Returns:
            str: hsm_id on success
            bool: False on failure
        """
        self._vp('withdraw: Sending request to Bank')
        pkt = "w" + struct.pack(">36s36sI", atm_id, card_id, amount)
        self.ser.write(pkt)

        while pkt not in "ONE":
            pkt = self.ser.read()

        if pkt != "O":
            self._vp('withdraw: request denied')
            return False
        pkt = self.ser.read(72)
        aid, cid = struct.unpack(">36s36s", pkt)
        self._vp('withdraw: Withdrawal accepted')
        return True
'''
    # Fox
    def provision_update(self, card_num, inner_layer_public_key, inner_layer_private_key, outer_layer_public_key, outer_layer_private_key, balance):
        pkt = struct.pack(">32s256s256s256s256s32s", format(card_num, 32), format(inner_layer_public_key, 256), format(inner_layer_private_key, 256), format(outer_layer_public_key, 256), format(outer_layer_private_key, 256), format(balance, 32))
        # total length is 1088 bytes
        self.ser.write("p" + pkt)
'''
    def stupid_provision_update(self):
        self.ser.write("f")


def format(value, size=256):
    if type(value) is str:
        return bytes(value, "utf-8")
    else:
        return (value).to_bytes(size, byteorder='little')


def process(value):
    return int.from_bytes(value, byteorder="little")
