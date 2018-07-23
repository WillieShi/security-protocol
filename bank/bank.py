""" Bank Server
This module implements a bank server interface
"""

import uuid
import db
import logging
from logging import info as log
import sys
import serial
import argparse
import struct
import ciphers
import random

ONION_SIZE = 256


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"
    transactionKey


    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)
        self.transactionKey = self.generate_key_pair()

    def encSend(message):
        message = ciphers.encrypt_aes(message, transactionKey)
        self.atm.write(message)

    def encRead(length):
        message = self.atm.read(length)
        return ciphers.decrypt_aes(message, transactionKey)

    def start(self):
        while True:
            command = self.atm.read()
            if command == 'w':
                log("Withdrawing")
                pkt = self.atm.read(76)
                atm_id, card_id, amount = struct.unpack(">36s36sI", pkt)
                self.withdraw(atm_id, card_id, amount)
            elif command == 'b':
                log("Checking balance")
                pkt = self.atm.read(72)
                atm_id, card_id = struct.unpack(">36s36s", pkt)
                self.check_balance(atm_id, card_id)
            elif command != '':
                self.atm.write(self.ERROR)

    def verify(self, atm_id, card_id, hash):
        if hash == self.db.get_hash(card_id_):
            rand = ciphers.random_with_N_digits(100)
            encSend(ciphers.encrypt_rsa(rand, self.db.get_outer_onion_public_key(card_id)))
            return rand == encRead(LENGTH)
        else:
            encSend("Invalid card/pin")
            return False


    def withdraw(self, atm_id, card_id, amount):
        if self.db.get_atm(atm_id) is None:
            self.atm.write(self.BAD)
            log("Invalid ATM ID")
            return

        balance = 0
        onion = self.db.get_onion(str(card_id))
        if onion is None:
            self.atm.write(self.BAD)
            log("Bad card ID")
        else:
            log("Valid balance check")
            self.encSend(onion)
            innerLayer = self.encRead(ONION_SIZE)
            balance = ciphers.decrypt_rsa(innerLayer, self.db.get_outer_onion_public_key)
            self.encSend(self.GOOD)

        if amount > balance:
            log("Invalid funds")
            self.encSend("Insufficient funds")
        else:
            self.encSend(balance-amount)
            self.db.set_onion(ciphers.encrypt_rsa(self.db.get_outer_onion_public_key(card_id),ciphers.encrypt_rsa(self.db.get_inner_onion_public_key(card_id), balance-amount)))

    def check_balance(self, atm_id, card_id): #finished
        if self.db.get_atm(atm_id) is None:
            self.atm.write(self.BAD)
            log("Invalid ATM ID")
            return

        onion = self.db.get_onion(str(card_id))
        if onion is None:
            self.atm.write(self.BAD)
            log("Bad card ID")
        else:
            log("Valid balance check")
            self.encSend(onion)
            innerLayer = self.encRead(ONION_SIZE)
            balance = ciphers.decrypt_rsa(innerLayer, self.db.get_outer_onion_public_key)
            self.encSend(self.GOOD)


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
    try:
        bank.start()
    except KeyboardInterrupt:
        print("Shutting down bank...")


if __name__ == "__main__":
    main()
