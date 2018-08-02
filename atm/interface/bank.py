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

    def provision_update(self, aes_key, IV, card_num, hashed_passkey, hashed_data):
        pkt = struct.pack(">32s16s16s32s32s", aes_key, IV, card_num, hashed_passkey, hashed_data)
        # total length is not 1088 bytes
        self.ser.write("p" + pkt)

    def stupid_provision_update(self):
        self.ser.write("f")


def format(value, size=256):
    if type(value) is str:
        return bytes(value, "utf-8")
    else:
        return (value).to_bytes(size, byteorder='little')


def process(value):
    return int.from_bytes(value, byteorder="little")
