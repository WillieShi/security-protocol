import logging
import sys
import cmd
from interface.card import NotProvisioned, AlreadyProvisioned
from interface import card, bank
import os
import json
import argparse

log = logging.getLogger('')
log.setLevel(logging.DEBUG)
log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(log_format)
log.addHandler(ch)


class ATM(cmd.Cmd, object):
    """Interface for ATM xmlrpc server

    Args:
        bank (Bank or BankEmulator): Interface to bank
        card (Card or CardEmulator): Interface to ATM card
    """
    intro = 'Welcome to your friendly ATM! Press ? for a list of commands\r\n'
    prompt = '1. Check Balance\r\n2. Withdraw\r\n3. Change PIN\r\n> '
    current_card_id = 0

    def __init__(self, bank, card, config_path="config.json",
                 billfile="billfile.out", verbose=False):
        super(ATM, self).__init__()
        self.bank = bank
        self.card = card
        self.config_path = config_path
        self.billfile = billfile
        self.verbose = verbose
        cfg = self.config()
        self.uuid = cfg["uuid"].decode("hex")
        self.dispensed = int(cfg["dispensed"])
        self.bills = cfg["bills"]
        self.update()

    def _vp(self, msg, log=logging.debug):
        print("here")
        if self.verbose:
            log(msg)

    def config(self):
        if not os.path.isfile(self.config_path):
            cfg = {"uuid": os.urandom(36).encode('hex'), "dispensed": 0,
                   "bills": ["example bill %5d" % i for i in range(128)]}
            return cfg
        else:
            with open(self.config_path, "r") as f:
                return json.loads(f.read())

    def update(self):
        with open(self.config_path, "w") as f:
            f.write(json.dumps({"uuid": self.uuid.encode("hex"), "dispensed": self.dispensed,
                                "bills": self.bills}))

    def verify(self, pin):
        """Verifies card with pin an private key

        Args:
            pin (int): the pin of the card

        Returns:
            bool: true if successfully verified
        """
        if self.pin_verify(pin, self.card.card_id_read()):
            self._vp("verified pin")
        else:
            return False
        self.current_card_id = self.card.card_id_read()
        self.bank.private_key_verify(self.current_card_id)
        self.card.card_verify_write(self.bank.private_key_verify_read())
        if self.bank.private_key_verify_write(self.card.read_random_num()):
            self._vp("verified private key")
            return True
        return False

    def check_balance(self):
        """Tries to check the balance of the account associated with the
        connected ATM card

        Args:
            pin (str): 8 digit PIN associated with the connected ATM card

        Returns:
            str: Balance on success
            bool: False on failure
        """

        if self.verify(self.get_pin()):
            print("Here")
            try:
                self._vp('check_balance: Requesting card_id using inputted pin')

                # get balance from bank if card accepted PIN
                if self.current_card_id:
                    self._vp('check_balance: Requesting balance from Bank')
                    outer_layer, signature = self.bank.outer_layer_read()
                    self.card.onion_write(outer_layer, signature)
                    inner_layer = self.card.onion_read()
                    self.bank.inner_layer_write(inner_layer)
                    print "Balance is: ", self.balance_read()
                    return self.balance_read()
                self._vp('check_balance failed')
                return False
            except NotProvisioned:
                self._vp('ATM card has not been provisioned!')
                return False

    def change_pin(self, old_pin, new_pin):
        """Tries to change the PIN of the connected ATM card

        Args:
            old_pin (str): 8 digit PIN currently associated with the connected
                ATM card
            new_pin (str): 8 digit PIN to associate with the connected ATM card

        Returns:
            bool: True on successful PIN change
            bool: False on failure
        """
        if self.verify(self.get_pin()):
            self.bank.pin_reset(new_pin)

    def withdraw(self, pin, amount):
        """Tries to withdraw money from the account associated with the
        connected ATM card

        Args:
            pin (str): 8 digit PIN currently associated with the connected
                ATM card
            amount (int): number of bills to withdraw

        Returns:
            list of str: Withdrawn bills on success
            bool: False on failure
        """
        if self.verify(self.get_pin()):
            try:
                self._vp('withdraw: Requesting card_id from card')
                card_id = self.card.card_id_read()

                # request UUID from HSM if card accepts PIN
                if card_id:
                    self._vp('withdraw: Requesting hsm_id from hsm')
                    self.check_balance()
                    if self.bank.withdraw_amount_write(amount):
                        with open(self.billfile, "w") as f:
                            self._vp('withdraw: Dispensing bills...')
                            for i in range(self.dispensed, self.dispensed + amount):
                                print(self.bills[i])
                                f.write(self.bills[i] + "\n")
                                self.bills[i] = "-DISPENSED BILL-"
                                self.dispensed += 1
                        self.update()
                        self.check_balance()
                        return True
                else:
                    self._vp('withdraw failed')
                    return False
            except ValueError:
                self._vp('amount must be an int')
                return False
            except NotProvisioned:
                self._vp('ATM card has not been provisioned!')
                return False

    def get_pin(self, prompt="Please insert 8-digit PIN: "):
        pin = ''
        while len(pin) != 8:
            pin = raw_input(prompt)
            if not pin.isdigit():
                print("Please only use digits")
                continue
        return pin

    def do_1(self, args):
        """Check Balance"""
        pin = self.get_pin()
        if not self.check_balance(pin):
            print("Balance lookup failed!")

    def do_2(self, args):
        """Withdraw"""
        pin = self.get_pin()

        amount = 'bad'
        while not amount.isdigit():
            amount = raw_input("Please enter valid amount to withdraw: ")

        if self.withdraw(pin, int(amount)):
            print("Withdraw success!")
        else:
            print("Withdraw failed!")

    def do_3(self, args):
        """Change PIN"""
        old_pin = self.get_pin()
        new_pin = self.get_pin("Please insert new 8-digit PIN: ")
        if self.change_pin(old_pin, new_pin):
            print("PIN change success!")
        else:
            print("PIN change failed!")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("bankport", help="Serial port connected to the bank")
    parser.add_argument("cardport", help="Serial port connected to the card")
    parser.add_argument("--config", default="config.json",
                        help="Path to the configuration file")
    parser.add_argument("--billfile", default="billfile.out",
                        help="File to print bills to")
    parser.add_argument("--verbose", action="store_true",
                        help="Print verbose debug information")
    args = parser.parse_args()
    return args.bankport, args.cardport, args.config, args.billfile, args.verbose


if __name__ == "__main__":
    b_port, c_port, config, billfile, verbose = parse_args()
    bank = bank.Bank(b_port, verbose=verbose)
    card = card.Card(c_port, verbose=verbose)
    atm = ATM(bank, card, config, billfile, verbose=verbose)
    # Generates the new AES key when it power cycles.
    bank.diffie_atm()
    atm.cmdloop()
