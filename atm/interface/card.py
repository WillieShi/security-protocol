# Card interface
import logging
import struct
import serial
import os


class NotProvisioned(Exception):
    pass


class AlreadyProvisioned(Exception):
    pass


class Card(object):
    """Interface for communicating with the ATM card

    Args:
        port (str, optional): Serial port connected to an ATM card
            Default is dynamic card acquisition
        verbose (bool, optional): Whether to print debug messages
    """
    CHECK_BAL = 1
    WITHDRAW = 2
    CHANGE_PIN = 3

    def __init__(self, port=None, verbose=False, baudrate=115200, timeout=2):
        self.ser = serial.Serial(port, baudrate, timeout=timeout)
        self.verbose = verbose

    def request_verify(self):
        """Requests card number and aes encrypted hashed passkey from card
        """

        self.ser.write("req")

        # card_id, encrypted_hashed_passkey = struct.unpack(">16s32s", self.ser.read(48))
        # return card_id, encrypted_hashed_passkey
        return os.urandom(16), os.urandom(32)

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    def _pull_msg(self, pkt_len):
        """Pulls message form the PSoC

        Returns:
            string with message from PSoC
        """
        return self.ser.read(pkt_len)

    def _send_op(self, op):
        """Sends requested operation to ATM card

        Args:
            op (int): Operation to send from [self.CHECK_BAL, self.WITHDRAW,
                self.CHANGE_PIN]
        """
        self._vp('Sending op %d' % op)
        self._push_msg(str(op))

    def provision(self, aes_key, IV, card_num, passkey):
        """Attempts to provision a new ATM card

        Args:
            uuid (str): New UUID for ATM card
            pin (str): Initial PIN for ATM card

        Returns:
            bool: True if provisioning succeeded, False otherwise
        """
        pkt = struct.pack(">32s16s16s16s", aes_key, IV, card_num, passkey)
        print(pkt)
        len(pkt)
        self.ser.write("prv" + pkt)

        self._vp('Provisioning complete')

        return True

    def stupid_provision(self):
        return True


def format(value, size=256):
    return value
