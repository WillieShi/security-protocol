""" Bank Server
This module implements a bank server interface

Key for codes used in communication functions:
pvc = pin_verification_read()
pkv = private_key_verification_read
ilw = inner_layer_write()
waw = withdraw_balance_modify(withdraw_amount_read(withdraw_amount))
rrb = request_read_balance()
pnr = pin_reset()
"""

import db
import logging
# from logging import info as log
import sys
import serial
import argparse
import struct
from Crypto.Util import number
import ciphers
import random


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"
    '''
    uptime_key is the AES key of the current uptime-session.
    A new uptime-session begins when the ATM is power-cycled.
    '''

    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)

    # Write function for when AES tunnel is not established.
    def default_write(self, msg):
        self.atm.write(msg)

    # Read function for when AES tunnel is not established.
    def default_read(self, size):
        return self.atm.read(size)

    # generates a prime number to be used in diffie hellman
    def generate_prime_number(self, n):
        generated_number = number.getPrime(n)
        return generated_number

    # Generates the modulus and base for Diffie Hellman using a prime number
    def diffie_hellman(self):
        modulus = self.generate_prime_number(2)
        base = self.generate_prime_number(3)
        return (modulus, base)

    # Bank-side diffie hellman function, which sends the modulus and base to ATM before computing agreed value.
    def diffie_bank(self):
        mod, base = self.diffie_hellman()
        #  Sends modulus and base to ATM
        self.default_write(struct.pack(">32s256s256s", format("dif_mod_base"), format(mod, 256), format(base, 256)))
        secret_number_b = random.randint(1, 9999)
        side_bank = (base**secret_number_b) % mod

        # Sends bank's half of diffie hellman to ATM.
        self.default_write(struct.pack(">32s256s", format("dif_side_bank"), format(side_bank, 256)))
        # Receives ATM's half of diffie hellman from ATM to compute final value.
        transaction_id, side_atm = struct.unpack("32s256s", self.default_read(288))
        # uptime_key_bank is the final bank-side agreed value for diffie hellman
        self.atm_key, self.atm_IV = (side_atm**secret_number_b) % mod, ciphers.generate_salt(16)

    # Links commands in ATM-Bank interface to functions in the bank
    # Three letter codes link interface commands to bank functions.
    # Initializes AES Key first upon power cycle.
    def start(self):
        self.diffie_bank()
        self.atm_key = 0
        while True:
            command = self.atm.read(3)
            if command == "ver":
                balance, card_id, data = self.verify()
            elif command == "wtd":
                self.withdraw(balance, card_id, data)
            elif command != "":
                self.atm.write(self.ERROR)

    def verify(self):
        encrypted_hashed_passkey, encrypted_hashed_data, encrypted_card_id = struct.unpack(">32s32s16s", self.default_read(80))
        # encrypted_hashed_passkey = process(encrypted_hashed_passkey)
        # encrypted_hashed_data = process(encrypted_hashed_data)
        card_id = ciphers.decrypt_aes(encrypted_card_id, self.atm_key)
        hashed_passkey = ciphers.decrypt_aes(encrypted_hashed_passkey, self.db.get_aes_key(card_id))
        hashed_data = ciphers.decrypt_aes(encrypted_hashed_data, self.atm_key)

        balance = ciphers.decrypt_aes(self.db.get_encrypted_balance(), hashed_data)

        if hashed_passkey == self.db.get_hashed_passkey(card_id):
            newIV = ciphers.generate_salt(16)
            self.default_write(struct.pack(">16s16s16s", ciphers.encrypt_aes(balance, self.db.get_aes_key(card_id), self.db.get_iv(card_id)), newIV, ciphers.encrypt_aes(balance, self.atm_key, self.atm_IV)))
            self.db.set_aes_key(card_id, gen_new_key(self.db.get_aes_key(card_id), balance))
            self.db.set_iv(card_id, newIV)
            return balance, card_id, hashed_data
        else:
            self.default_write("Nice try kid, papa john taught me all the tricks")

    def withdraw(self, balance, card_id, hashed_data):
        encrypted_withdraw_amount = struct.unpack(">16s", self.default_read(16))
        withdraw_amount = ciphers.decrypt_aes(encrypted_withdraw_amount, self.db.get_aes_key(card_id), self.db.get_iv(card_id))

        if balance > withdraw_amount:
            new_balance = balance - withdraw_amount
            newIV = ciphers.generate_salt(16)
            self.default_write(struct.pack(">16s16s16s", ciphers.encrypt_aes(new_balance, self.db.get_aes_key(card_id), self.db.get_iv(card_id)), newIV, ciphers.encrypt_aes(new_balance, self.atm_key, self.atm_IV)))
            self.db.set_aes_key(card_id, gen_new_key(self.db.get_aes_key(card_id), new_balance))
            self.db.set_iv(card_id, newIV)
            self.db.set_encrypted_balance(card_id, ciphers.encrypt_aes(new_balance, hashed_data))
        else:
            self.default_write("You're broke ponyboy")


def gen_new_key(old_key, balance):
    return ciphers.hash_message(format(old_key) + format(balance))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", help="Serial port ATM is connected to")
    parser.add_argument("--baudrate", default=115200, help="Optional baudrate (default 115200)")
    return parser.parse_args()


def format(value, size=256):
    if type(value) is str:
        return bytes(value, "utf-8")
    else:
        return (value).to_bytes(size, byteorder='little')


def process(value):
    return int.from_bytes(value, byteorder="little")


def main():
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(log_format)
    log.addHandler(ch)

    args = parse_args()

    bank = Bank(args.port, args.baudrate)
    while True:
        try:
            bank.start()
        except KeyboardInterrupt:
            print("Shutting down bank...")


if __name__ == "__main__":
    main()
