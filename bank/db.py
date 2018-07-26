""" DB
This module implements an interface to the bank_server database.
"""

import json
import os.path


class DB(object):
    """Implements a Database interface for the bank server and admin interface"""
    def __init__(self, db_path="bank.json"):
        self.path = db_path

    def close(self):
        """close the database connection"""
        pass

    def init_db(self):
        """initialize database with file at filepath"""
        with open(self.path, 'w') as f:
            f.write(json.dumps({'atms': {}, 'cards': {}, 'storage': {},}))

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

    def get_atm(self, atm_id):
        """get atm_id of atm: atm_id
        this is an obviously dumb function but maybe it can be expanded...

        Returns:
            (string or None): Returns atm_id on Success. None otherwise.
        """
        if self.get_atm_num_bills(atm_id):
            return atm_id
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
    def get_onion(self, card_id):

        return self.read("cards", card_id, "onion")

    def set_onion(self, card_id, value):

        return self.modify("cards", card_id, "onion", value)

    def get_hash(self, card_id):

        return self.read("cards", card_id, "hash")

    def set_hash(self, card_id, value):

        return self.modify("cards", card_id, "hash", value)

    def get_signature(self, card_id):

        return self.read("cards", card_id, "signature")

    def set_signature(self, card_id, value):

        return self.modify("cards", card_id, "signature", value)

    def get_outer_onion_public_key(self, card_id):

        return self.read("cards", card_id, "outer_onion_public_key")

    def set_outer_onion_public_key(self, card_id, value):

        return self.modify("cards", card_id, "outer_onion_public_key", value)

    def get_inner_onion_private_key(self, card_id):

        return self.read("cards", card_id, "inner_onion_private_key")

    def set_inner_onion_private_key(self, card_id, value):

        return self.modify("cards", card_id, "inner_onion_private_key", value)

    def get_inner_onion_public_key(self, card_id):

        return self.read("cards", card_id, "inner_onion_public_key")

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
        return self.modify('cards', card_id, ["bal"], [amount])

    def admin_create_atm(self, atm_id):
        """create atm with atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("atms", atm_id, ["nbills"], [128])

    def admin_get_balance(self, card_id):
        """get balance of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("cards", card_id, "bal")

    def admin_set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["bal"], [balance])
