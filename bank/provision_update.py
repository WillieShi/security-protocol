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

    atm = serial.Serial(port, baudrate=115200, timeout=5)

    try:
        db = DB(db_path=db_file)
        admin_db = Admin_DB(db_path=admin_db_file)
        db.init_db()
        admin_db.init_db()
        while True:
            print("Listening for provisioning info...")
            pkt = atm.read()
            print(pkt)
            if pkt == b'p':
                print("Reading provisioning info...")
                pkt = atm.read(128)
                print(pkt)
                print(len(pkt))
                aes_key, IV, card_id, hashed_passkey, hashed_data = struct.unpack(">64s32s32s64s64s", pkt)

                aes_key = process_to_int(aes_key)
                IV = process_to_int(IV)
                hashed_passkey = process_to_int(aes_key)
                hashed_data = process_to_int(hashed_data)

                print("parts", aes_key, IV, card_id, hashed_passkey, hashed_data)

                db.set_aes_key(card_id, aes_key)
                db.set_iv(card_id, IV)
                db.set_balance_iv(card_id, IV)
                db.set_hashed_passkey(card_id, hashed_passkey)
                db.set_encrypted_balance(card_id, ciphers.encrypt_aes(1000, hashed_data, db.get_balance_iv(card_id)))
                admin_db.set_hashed_data(card_id, hashed_data)

                break

            # card_num, inner_layer_public_key, inner_layer_private_key, outer_layer_public_key, outer_layer_private_key, balance = struct.unpack(">36I256I256I256I256I32I", pkt)

                print("Account added!")
    except KeyboardInterrupt:
        print("Shutting down...")


# Used to reformat inputs to bytes, which can then be packed using struct
def format(value, size=256):
    if type(value) is str:
        return value.encode("hex")
    else:
        return hex(value)


# Converts bytes back into int, only works on int
def process_to_string(value):
    return bytes.fromhex('4a4b4c').decode('utf-8')


def process_to_int(value):
    return int(value, 16)
