""" DB
This module implements an interface to the bank_server database.
"""

import json
import os.path
import ciphers
import admin_db


class DB(object):
    """Implements a Database interface for the bank server and admin interface"""
    def __init__(self, db_path="bank.json"):
        self.path = db_path
        self.admin_db = admin_db.Admin_DB(db_path=db_path)

    def close(self):
        """close the database connection"""
        pass

    def init_db(self):
        """initialize database with file at filepath"""
        with open(self.path, 'w') as f:
            f.write(json.dumps({'atms': {}, 'cards': {}, 'storage': {}}))

    def exists(self):
        return os.path.exists(self.path)

    def modify(self, table, k, subks, vs):
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            for subk, v in zip(subks, vs):
                if k not in db[table]:
                    db[table][k] = {}
                db[table][k][subk] = v
        except KeyboardInterrupt:
            return False

        with open(self.path, 'w') as f:
            f.write(json.dumps(db))

        return True

    def read(self, table, k, subk):
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            return db[table][k][subk]
        except KeyError:
            return None

    ############################
    # BANK INTERFACE FUNCTIONS #
    ############################

    def get_atm_num_bills(self, atm_id):
        """get number of bills in atm: atm_id

        Returns:
            (string or None): Returns num_bills on Success. None otherwise.
        """
        return self.read("atms", atm_id, "bills")

    def set_atm_num_bills(self, atm_id, balance):
        """set number of bills in atm: atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("atms", atm_id, "bills", balance)

    ####################
    # CUSTOM FUNCTIONS #
    ####################
    # Contains the balance in the double layer RSA.
    def get_onion(self, card_id):
        return self.read("cards", card_id, "onion")

    # Puts onion in the database.
    def set_onion(self, card_id, value):
        return self.modify("cards", card_id, "onion", value)

    # Gets the hash that contains the card ID and PIN from database.
    def get_hash(self, card_id):
        return self.read("cards", card_id, "hash")

    # Sets the hash for card ID and PIN.
    def set_hash(self, card_id, value):
        return self.modify("cards", card_id, "hash", value)

    # Gets the public key for the outer RSA layer.
    def get_outer_onion_public_key(self, card_id):
        return self.read("cards", card_id, "outer_onion_public_key")

    # Sets the public key for the outer RSA layer.
    def set_outer_onion_public_key(self, card_id, value):
        return self.modify("cards", card_id, "outer_onion_public_key", value)

    # Gets the private key for the inner RSA layer.
    def get_inner_onion_private_key(self, card_id):
        return self.read("cards", card_id, "inner_onion_private_key")

    # Sets the private key for the inner RSA layer.
    def set_inner_onion_private_key(self, card_id, value):
        return self.modify("cards", card_id, "inner_onion_private_key", value)

    # Gets the public key for the inner RSA layer.
    def get_inner_onion_public_key(self, card_id):
        return self.read("cards", card_id, "inner_onion_public_key")

    # Sets the public key for the inner RSA layer.
    def set_inner_onion_public_key(self, card_id, value):
        return self.modify("cards", card_id, "inner_onion_public_key", value)

    #############################
    # ADMIN INTERFACE FUNCTIONS #
    #############################

    def admin_create_account(self, card_id, amount):
        """create account with account_name, card_id, and amount

        Returns:
            (bool): Returns True on Success. False otherwise.
        """

        return self.modify('cards', card_id, ["onion"], [ciphers.encrypt_rsa(ciphers.encrypt_rsa(amount, self.get_inner_onion_public_key(card_id)), self.get_outer_onion_public_key(card_id))])

    def admin_create_atm(self, atm_id):
        """create atm with atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("atms", atm_id, ["bills"], [128])

    def admin_get_balance(self, card_id):
        """get balance of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return ciphers.decrypt_rsa(ciphers.decrypt_rsa(self.read("cards", card_id, "onion"), self.get_inner_onion_private_key(card_id)), self.admin_db.get_outer_onion_private_key())

    def admin_set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["onion"], [ciphers.encrypt_rsa(ciphers.encrypt_rsa(balance, self.get_inner_onion_public_key(card_id)), self.get_outer_onion_public_key(card_id))])
