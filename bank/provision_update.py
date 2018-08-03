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

    atm = serial.Serial(port, baudrate, timeout=5)

    try:
        while True:
            print("Listening for provisioning info...")
            while atm.read() != "p":
                continue

            print("Reading provisioning info...")
            db = DB(db_file=db_file)
            admin_db = Admin_DB(admin_db_file=admin_db_file)

            aes_key, IV, card_id, hashed_passkey, hashed_data = struct.pack(">32s16s16s32s32s", atm.read(128))
            db.set_aes_key(card_id, aes_key)
            db.set_iv(card_id, IV)
            db.set_balance_iv(card_id, IV)
            db.set_hashed_passkey(card_id, hashed_passkey)
            db.set_encrypted_balance(card_id, ciphers.encrypt_aes(1000, hashed_data))
            admin_db.set_hashed_data(hashed_data)

            # card_num, inner_layer_public_key, inner_layer_private_key, outer_layer_public_key, outer_layer_private_key, balance = struct.unpack(">36I256I256I256I256I32I", pkt)

            print("Account added!")
    except KeyboardInterrupt:
        print("Shutting down...")
