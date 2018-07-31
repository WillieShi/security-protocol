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
from logging import info as log
import sys
from serial import Serial
import argparse
import struct
from Crypto.Util import number
import ciphers


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"
    '''
    uptime_key is the AES key of the current uptime-session.
    A new uptime-session begins when the ATM is power-cycled.
    '''
    uptime_key_bank = 0

    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)
        self.transactionKey = self.generate_key_pair()

    # Write function for when AES tunnel is not established.
    def default_write(self, msg):
        self.atm.write(msg)

    # Read function for when AES tunnel is not established.
    def default_read(self, size):
        return self.atm.read(size)

    # Encrypts a message in AES using the current AES key.
    def aes_write(self, message):
        message = ciphers.encrypt_aes(message, self.uptime_key)
        self.atm.write(message)

    # Decrypts AES. If it receives an invalid ATM ID (CARD# or PIN) it returns.
    def aes_read(self, length):
        if self.db.get_atm(self.atm_id) is None:
            self.atm.write(self.BAD)
            log("Invalid ATM ID")
            return
        message = self.atm.read(length)
        return ciphers.decrypt_aes(message, self.uptime_key)

    # generates a prime number to be used in diffie hellman
    def generate_prime_number(n):
        generated_number = number.getPrime(n)
        return generated_number

    # Generates the modulus and base for Diffie Hellman using a prime number
    def diffie_hellman(self):
        modulus = self.generate_prime_number(617)
        base = self.generate_prime_number(617)
        return (modulus, base)

    # Bank-side diffie hellman function, which sends the modulus and base to ATM before computing agreed value.
    def diffie_bank(self):
        mod, base = self.diffie_hellman()
        #  Sends modulus and base to ATM
        self.default_write(struct.pack("32s256I256I", "dif_mod_base", mod, base))
        secret_number_b = ciphers.generate_salt(15)
        side_bank = (base**secret_number_b) % mod
        # Sends bank's half of diffie hellman to ATM.
        self.default_write(struct.pack("32s256I", "dif_side_bank", side_bank))
        # Receives ATM's half of diffie hellman from ATM to compute final value.
        transaction_id, side_atm = struct.unpack("32s256I", self.default_read(288))
        # uptime_key_bank is the final bank-side agreed value for diffie hellman
        self.uptime_key_bank = (side_atm**secret_number_b) % mod

    # Links commands in ATM-Bank interface to functions in the bank
    # Three letter codes link interface commands to bank functions.
    # Initializes AES Key first upon power cycle.
    def start(self):
        self.diffie_bank()
        while True:
            card_id = 0
            verified = False
            balance = 0
            rand_num = 0
            command = self.atm.read(3)
            if command == "pvc":
                card_id = self.pin_verification_read(card_id)
                if card_id is False:
                    self.send_verification_result(False)
            elif command == "pkw":
                verified = self.private_key_verification_read(rand_num, card_id)
                self.send_verification_result(verified)
            elif command == "pkv":
                rand_num = self.private_key_verify_write(card_id)
            elif command == "ilw" and verified:
                balance = self.inner_layer_read(card_id)
                self.balance_write(balance)
            elif command == "waw" and verified:
                self.withdraw_balance_modify(balance, self.withdraw_amount_read(), card_id)
            elif command == "rrb" and verified:
                self.outer_layer_write(card_id)
            elif command == "pnr" and verified:
                self.pin_change(card_id)
            elif command == "rst":
                break
            elif command != "":
                self.atm.write(self.ERROR)

    # Sends all verification results of every applicaple transaction.
    def send_verification_result(self, good):
        self.aes_write(struct.pack(">32s?", "send_verification_result", good))

    # Changes the user's PIN based on user input.
    def pin_change(self, card_id):
        transaction_id, pin = struct.unpack(">32s32I", self.self.aes_read(64))
        self.db.set_hash(card_id, ciphers.hash_message(card_id + pin))

    # Checks to see if card ID and PIN match a legitimate account in the bank database.
    def pin_verification_read(self, card_id):
        transaction_id, card_id, hash = struct.unpack(">32s32I32I", self.aes_read(96))
        if hash == self.db.get_hash(card_id):
            return card_id
        return False

    # Generates a random number and encrypts it with RSA encryption that a valid card would have the private key to.
    def private_key_verification_write(self, card_id):
        rand_num = ciphers.generate_salt(32)
        self.aes_write(struct.pack(">32s256I256I", "private_key_verification_write", ciphers.encrypt_rsa(rand_num, self.db.get_outer_onion_public_key(card_id)), ciphers.sign_data(self.db.get_inner_onion_private_key(card_id))))
        return rand_num

    # Compares the random number sent by card (through ATM) to the originally generated random number. If they are equal, the card is a valid card.
    def private_key_verification_read(self, rand_num, card_id):
        transaction_id, cand_rand_num = struct.unpack(">32s32I", self.aes_read(64))
        if rand_num == cand_rand_num:
            return True
        return False

    # Encrypts data with the outer layer of the onion in RSA.
    def outer_layer_write(self, card_id):
        val = struct.pack(">32s512I256I", "outer_layer_write", self.db.get_onion(card_id), ciphers.sign_data(self.db.get_inner_onion_private_key(card_id)))
        self.aes_write(val)

    # Decrypts the inner layer of the onion (RSA).
    def inner_layer_read(self, card_id):
        transaction_id, enc_val = struct.unpack(">32s256I", self.aes_read(288))
        return ciphers.decrypt_rsa(enc_val, self.db.get_inner_onion_private_key(card_id))

    # Reads the withdraw request to get the amount the user would like to withdraw.
    def withdraw_amount_read(self):
        transaction_id, withdraw_amount = struct.unpack(">32s32I", self.aes_read(64))
        return withdraw_amount

    # Calculates the new balance using the withdraw amount. Only passes if the user has enough money to withdraw their requested amount.
    def withdraw_balance_modify(self, balance, withdraw_amount, card_id):
        if(balance - withdraw_amount >= 0):
            new_balance = balance - withdraw_amount
            self.db.set_onion(ciphers.encrypt_rsa(ciphers.encrypt_rsa(new_balance, self.db.get_inner_onion_public_key(card_id)), self.db.get_outer_onion_public_key(card_id)))
            return new_balance
        else:
            return "Bad, try again"  # fix this later, error system

    # Encrypts final balance with AES in preparation to send to ATM.
    def balance_write(self, balance):
        val = struct.pack(">32s32I", "balance_write", balance)
        self.aes_write(val)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", help="Serial port ATM is connected to")
    parser.add_argument("--baudrate", help="Optional baudrate (default 115200)")
    return parser.parse_args()


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
