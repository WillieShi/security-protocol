from db import DB
from admin_db import Admin_DB
import argparse
import serial
import struct
import ciphers


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", help="serial port to connect to")
    parser.add_argument("--baudrate", type=int, default=115200,
                        help="Baudrate of serial port")
    parser.add_argument("--db-file", default="bank.json",
                        help="Name of bank database file")
    parser.add_argument("--admin-db-file", default="admin-bank.json",
                        help="Name of bank admin database file")
    args = parser.parse_args()
    return args.port, args.baudrate, args.db_file, args.admin_db_file


if __name__ == "__main__":
    port, baudrate, db_file, admin_db_file = parse_args()

    atm = serial.serial(port, baudrate, timeout=5)

    try:
        while True:
            print("Listening for provisioning info...")
            while atm.read() != "p":
                continue

            print("Reading provisioning info...")
            pkt = atm.read(1088)
            # card_num, inner_layer_public_key, inner_layer_private_key, outer_layer_public_key, outer_layer_private_key, balance = struct.unpack(">36I256I256I256I256I32I", pkt)

            struct.unpack()

            card_num = int.from_bytes(ciphers.generate_salt(32))

            print("card number is" + card_num)

            private_inner_layer_key, public_inner_layer_key = ciphers.generate_key()
            private_outer_layer_key, public_outer_layer_key = ciphers.generate_key()

            print("card private key is " + private_outer_layer_key)

            print("Updating database...")
            db = DB(db_file)
            admin_db = Admin_DB()
            db.admin_create_account(card_num, 978134)
            db.set_inner_onion_public_key(card_num, public_inner_layer_key)
            db.set_inner_onion_private_key(card_num, private_inner_layer_key)
            db.set_outer_onion_public_key(card_num, public_outer_layer_key)
            admin_db.set_outer_onion_private_key(card_num, private_outer_layer_key)
            print("Account added!")
    except KeyboardInterrupt:
        print("Shutting down...")
