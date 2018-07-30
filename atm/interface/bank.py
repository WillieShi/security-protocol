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
import secrets
import ciphers


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
        self.set.write(msg)

    # Read function for when AES tunnel is not established.
    def default_read(self, size):
        return self.set.read(size)

    # Sends AES encrypted message.
    def aes_write(self, msg):
        self.set.write(ciphers.encrypt_aes(msg, self.uptime_key))

    # Receives and decrypts AES from message.
    def aes_read(self, size):
        return ciphers.decrypt_aes(self.set.read(size), self.uptime_key)

    # The ATM-side diffie hellman function, which receives the modulus and base from the bank.
    # Performs computations after receving modulus and base from bank.
    def diffie_atm(self):
        # Receives modulus and base from bank.
        transaction_id, mod, base = struct.unpack(">32s256I256I", self.default_read(544))
        secret_number_a = secrets.randbelow(9999)
        side_atm = (base**secret_number_a) % mod
        # Receives bank's half of diffie hellman from bank to compute final value.
        transaction_id, side_bank = struct.unpack("32s256I", self.default_read(288))
        # Sends ATM's half of diffie hellman to bank.
        self.default_write(struct.pack("32s256I", "dif_side_atm", side_atm))
        # uptime_key_atm is the final ATM-side agreed value for diffie hellman
        self.uptime_key_atm = (side_bank**secret_number_a) % mod

    # Encrypts the verification number to test to see if the card is legitimate.
    def private_key_verify(self, card_id):
        self.aes_write("pkv" + struct.pack(">32s32I", "private_key_verify", card_id))

    # Sends hashed card ID and PIN to the bank.
    def pin_verify(self, pin, card_id):
        val = "pvc" + struct.pack(">32s32I32I", "pin_verify", card_id, ciphers.hash_message(card_id+pin))
        self.aes_write(val)
        transaction_id, result = struct.unpack(">32s?", self.aes_read(33))
        return result

    # Decrypts the AES on the random number to send to the card.
    def private_key_verify_read(self):
        transaction_id, random_num, signature = struct.unpack(">32s256I256I", self.aes_read(544))
        return random_num, signature

    # private_key_verify() sends the random_num the card decrypted back to bank
    def private_key_verify_write(self, random_num):
        val = "pkw" + struct.pack(">32s32I", "private_key_verify_write", random_num)
        self.aes_write(val)

    # Writes the inner onion layer to the bank.
    def inner_layer_write(self, inner_layer):
        val = "ilw" + struct.pack(">32s256I", "send_inner_layer", inner_layer)
        self.aes_write(val)

    # Decrypts the AES on the onion from the bank to send to the card.
    def outer_layer_read(self):
        transaction_id, outer_layer, signature = struct.unpack(">32s512I256I", self.aes_read(800))
        return outer_layer, signature

    # Encrypts the withdraw amount requested by the card to send to the bank.
    def withdraw_amount_write(self, amount):
        val = "waw" + struct.pack(">32s32I", "send_withdraw_amount", amount)
        self.aes_write(val)

    # Sends a request to the bank to check the balance.
    def request_read_balance(self):
        val = "rrb" + struct.pack(">32s", "request_read_balance")
        self.aes_write(val)

    # Sends a request to the bank to reset the PIN.
    def pin_reset(self, pin):
        val = "pnr" + struct.pack(">32s32I", "pin_reset", "pin")
        self.aes_write(val)

    # Sends the balance to the card from the bank.
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

    def provision_update(self, card_num, inner_layer_public_key, inner_layer_private_key, outer_layer_public_key, outer_layer_private_key, balance):
        pkt = struct.pack(">32I256I256I256I256I32I", card_num, inner_layer_public_key, inner_layer_private_key, outer_layer_public_key, outer_layer_private_key, balance)
        # total length is 1088 bytes
        self.ser.write("p" + pkt)

    def stupid_provision_update(self):
        self.ser.write("f")
