"""Backend of ATM interface for xmlrpc
Key
pvc = pin_verify()
pkv = private_key_verify()
ilw = inner_layer_write()
bbb = check_balance()
www = withdraw()

"""

import logging
import struct
import serial
import ciphers.py
# may or may not need .py


class Bank:
    """Interface for communicating with the bank

    Args:
        port (serial.Serial): Port to connect to
    """
    uptime_key = 0

    def __init__(self, port, verbose=False):
        self.ser = serial.Serial(port)
        self.verbose = verbose

    def aes_write(self, msg):
        self.set.write(ciphers.encrypt_aes(msg, self.uptime_key))

    def aes_read(self, msg, size):
        return ciphers.decrypt_aes(self.set.read(size), self.uptime_key)

    # The ATM-side diffie hellman function, which receives the modulus and base from the bank.
    # Performs computations after receving modulus and base from bank.
    def diffie_atm():
        mod, bas = "getting the mod and base"
        # insert read (mod, bas) from bank

        secret_number_a = secrets.randbelow(9999)
        side_atm = (bas**secret_number_a) % mod
        # insert write (side_atm) to bank
        # insert read (side_bank) from bank
        # final_atm is the final atm side key for diffie hellman
        final_atm = (side_bank**secret_number_a) % mod
        return final_atm

    def private_key_verify(self, card_id):
        self.aes_write("pkv" + struct.pack(">32s32I", "private_key_verify", card_id))

    def pin_verify(self, pin, card_id):
        val = "pvc" + struct.pack(">32s32I32I", "pin_verify", card_id, ciphers.hash_message(card_id+pin))
        self.aes_write(val)
        transaction_id, result = struct.unpack(">32s?", self.aes_read(33))
        return result

    def private_key_verify_read(self):
        transaction_id, random_num, signature = struct.unpack(">32s256I256I", self.aes_read(544))
        return random_num, signature

    # private_key_verify() sends the random_num the card decrypted back to bank
    def private_key_verify_write(self, random_num):
        val = "pkw" + struct.pack(">32s32I", "private_key_verify_write", random_num)
        self.aes_write(val)

    def inner_layer_write(self, inner_layer):
        val = "ilw" + struct.pack(">32s256I", "send_inner_layer", inner_layer)
        self.aes_write(val)

    def outer_layer_read(self):
        transaction_id, outer_layer, signature = struct.unpack(">32s512I256I", self.aes_read(800))
        return outer_layer, signature

    def withdraw_amount_write(self, amount):
        val = "waw" + struct.pack(">32s32I", "send_withdraw_amount", amount)
        self.aes_write(val)

    def request_read_balance(self):
        val = "rrb" + struct.pack(">32s", "request_read_balance")
        self.aes_write(val)

    def pin_reset(self, pin):
        val = "pnr" + struct.pack(">32s32I", "pin_reset", "pin")
        self.aes_write(val)

    def balance_read(self):
        transaction_id, balance = struct.unpack(">32s32I")
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

    def provision_update(self, uuid, pin, balance):
        pkt = struct.pack(">36s8sI", uuid, pin, balance)
        self.ser.write("p" + pkt)
