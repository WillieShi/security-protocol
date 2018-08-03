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
        if not self.exists():
            self.init_db()

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

    def get_atm(self, atm_id):
        return 1000

    def get_atm_num_bills(self, atm_id):
        """get number of bills in atm: atm_id

        Returns:
            (string or None): Returns num_bills on Success. None otherwise.
        """
        return 1000

    def set_atm_num_bills(self, atm_id, balance):
        """set number of bills in atm: atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return True

    ####################
    # CUSTOM FUNCTIONS #
    ####################
    # Contains the balance in the double layer RSA.
    def get_encrypted_balance(self, card_id):
        return self.read("cards", card_id, "encrypted_balance")

    # Puts onion in the database.
    def set_encrypted_balance(self, card_id, value):
        return self.modify("cards", card_id, "encrypted_balance", value)

    def get_hashed_passkey(self, card_id):
        return self.read("cards", card_id, "hashed_passkey")

    # Puts onion in the database.
    def set_hashed_passkey(self, card_id, value):
        return self.modify("cards", card_id, "hashed_passkey", value)

    def get_aes_key(self, card_id):
        return self.read("cards", card_id, "aes_key")

    # Puts onion in the database.
    def set_aes_key(self, card_id, value):
        return self.modify("cards", card_id, "aes_key", value)

    def get_iv(self, card_id):
        return self.read("cards", card_id, "iv")

    # Puts onion in the database.
    def set_iv(self, card_id, value):
        return self.modify("cards", card_id, "iv", value)

    def get_balance_iv(self, card_id):
        return self.read("cards", card_id, "balance_iv")

    def set_balance_iv(self, card_id, value):
        return self.modify("cards", card_id, "balance_iv", value)

    #############################
    # ADMIN INTERFACE FUNCTIONS #
    #############################

    def admin_create_account(self, card_id, amount):
        """create account with account_name, card_id, and amount

        Returns:
            (bool): Returns True on Success. False otherwise.
        """

        return self.modify('cards', card_id, ["encrypted_balance"], ciphers.encrypt_aes(amount, self.admin_db.get_hashed_data(card_id)))

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
        return ciphers.decrypt_aes(self.get_encrypted_balance(card_id), self.admin_db.get_hashed_data(card_id))

    def admin_set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["encrypted_balance"], [ciphers.encrypt_aes(balance, self.admin_db.get_hashed_data(card_id))])
