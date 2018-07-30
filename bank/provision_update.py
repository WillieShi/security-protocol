from db import DB
from admin_db import Admin_DB
import argparse
import serial
import struct


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
            card_num, inner_layer_public_key, inner_layer_private_key, outer_layer_public_key, outer_layer_private_key, balance = struct.unpack(">36I256I256I256I256I32I", pkt)

            print("Updating database...")
            db = DB(db_file)
            admin_db = Admin_DB()
            db.admin_create_account(card_num, balance)
            db.set_inner_onion_public_key(card_num, inner_layer_public_key)
            db.set_inner_onion_private_key(card_num, inner_layer_private_key)
            db.set_outer_onion_public_key(card_num, outer_layer_public_key)
            admin_db.set_outer_onion_private_key(card_num, outer_layer_private_key)
            print("Account added!")
    except KeyboardInterrupt:
        print("Shutting down...")
