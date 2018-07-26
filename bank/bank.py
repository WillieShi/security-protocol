""" Bank Server
This module implements a bank server interface

Key
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
import serial
import argparse
import struct
import ciphers


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"
    uptime_Key = 0

    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)
        self.transactionKey = self.generate_key_pair()

    def aes_write(self, message):
        message = ciphers.encrypt_aes(message, self.uptime_key)
        self.atm.write(message)

    def aes_read(self, length):
        if self.db.get_atm(self.atm_id) is None:
            self.atm.write(self.BAD)
            log("Invalid ATM ID")
            return
        message = self.atm.read(length)
        return ciphers.decrypt_aes(message, self.uptime_key)

    def start(self):
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

    def send_verification_result(self, good):
        self.aes_write(struct.pack(">32s?", "send_verification_result", good))

    def pin_change(self, card_id):
        transaction_id, pin = struct.unpack(">32s32I", self.self.aes_read(64))
        self.db.set_hash(card_id, ciphers.hash_message(card_id + pin))

    def pin_verification_read(self, card_id):
        transaction_id, card_id, hash = struct.unpack(">32s32I32I", self.aes_read(96))
        if hash == self.db.get_hash(card_id):
            return card_id
        return False

    def private_key_verification_write(self, card_id):
        rand_num = ciphers.random_with_N_bytes(32)
        self.aes_write(struct.pack(">32s256I", "private_key_verification_write", ciphers.encrypt_rsa(rand_num, self.db.get_outer_onion_public_key(card_id))))
        return rand_num
        # self.aes_write may cause problems due to no "self." appended to the beginning.

    def private_key_verification_read(self, rand_num, card_id):
        transaction_id, cand_rand_num = struct.unpack(">32s32I", self.aes_read(64))
        if rand_num == cand_rand_num:
            return True
        return False

    def outer_layer_write(self, card_id):
        val = struct.pack(">32s512I", "outer_layer_write", self.db.get_onion(card_id))
        self.aes_write(val)

    def inner_layer_read(self, card_id):
        transaction_id, enc_val = struct.unpack(">32s256I", self.aes_read(288))
        return ciphers.decrypt_rsa(enc_val, self.db.get_inner_onion_private_key(card_id))

    def withdraw_amount_read(self):
        transaction_id, withdraw_amount = struct.unpack(">32s32I", self.aes_read(64))
        return withdraw_amount

    def withdraw_balance_modify(self, balance, withdraw_amount, card_id):
        if(balance - withdraw_amount >= 0):
            new_balance = balance - withdraw_amount
            self.db.set_onion(ciphers.encrypt_rsa(ciphers.encrypt_rsa(new_balance, self.db.get_inner_onion_public_key(card_id)), self.db.get_outer_onion_public_key(card_id)))
            return new_balance
        else:
            return "Bad, try again"  # fix this later, error system

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
