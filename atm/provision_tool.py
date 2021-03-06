from interface.card import Card
from interface.bank import Bank
import argparse
import ciphers
import sys
import struct


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("balance", type=int,
                        help="Starting balance for account")
    parser.add_argument("cport", help="Serial port to the card")
    parser.add_argument("bport", help="Serial port to the bank")
    parser.add_argument("--cbaud", type=int, default=115200,
                        help="Baudrate of serial connection to the card")
    parser.add_argument("--bbaud", type=int, default=115200,
                        help="Baudrate of serial connection to the bank")
    parser.add_argument("--pin", default="12345678",
                        help="Initial pin to program (default 12345678)")
    args = parser.parse_args()
    return args.balance, args.cport, args.bport, args.cbaud, args.bbaud, args.pin


def bytesize(value):
    if type(value) is str:
        return len(bytes(value, "utf-8"))
    if type(value) is float:
        return sys.getsizeof(struct.pack("d", value))
    else:
        n = 0
        while value != 0:
            value >>= 8
            n = n + 1
        return n


if __name__ == "__main__":
    balance, c_port, b_port, c_baud, b_baud, pin = parse_args()
    # provision card
    print "Provisioning card..."
    card = Card(c_port, baudrate=c_baud, verbose=True)

    card_num = ciphers.generate_salt(32)

    private_inner_layer_key, public_inner_layer_key = ciphers.generate_key()
    private_outer_layer_key, public_outer_layer_key = ciphers.generate_key()

    card.provision(card_num, private_outer_layer_key, public_inner_layer_key)
    # card.stupid_provision()
    print "Card provisioned!"
    # update bank
    print "Updating bank..."
    bank = Bank(b_port)
    bank.provision_update(card_num, public_inner_layer_key, private_inner_layer_key, public_outer_layer_key, private_outer_layer_key, balance)
    # bank.stupid_provision()

    print "Provisioning successful"
    print "Card already provisioned!"
