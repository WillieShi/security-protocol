""" DB
This module implements an interface to the bank_server database.
"""

import json
import os.path


class Admin_DB(object):
    """Implements a Database interface for the bank server and admin interface"""
    def __init__(self, db_path="admin_access.json"):
        self.path = db_path

    def close(self):
        """close the database connection"""
        pass

    def init_db(self):
        """initialize database with file at filepath"""
        with open(self.path, 'w') as f:
            f.write(json.dumps({'cards': {}}))

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

# Private key generators for the backup database(RSA)
    def get_hashed_data(self, card_id):
        return self.read("cards", card_id, "hashed_data")

    def set_hashed_data(self, card_id, value):
        return self.modify("cards", card_id, "hashed_data", value)
