# Card interface
import logging
import struct
import time
import serial


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

    def write(self, msg):
        """Wrapper function to write to the card

        Args:
            msg (integer): msg to send to the card
        """
        self.ser.write(msg)

    def read(self, size):
        """Wrapper function to read from the card

        Args:
            size (int): size of message to read in bytes

        Returns:
            bool: true if successfully verified
        """
        return self.ser.read(size)

    def card_id_read(self):
        """Reads card number from the card

        Returns:
            int: card number
        """
        self.write("cir")
        card_id = struct.unpack(">32I", self.read(32))
        return card_id

    # decrypts the random num received from bank to verify card
    def read_random_num(self, encrypted_randnum):
        random_num = struct.unpack(">32I", self.read(32))
        return random_num

    # encrypts decrypted random num w/ AES to send to bank
    def card_verify_write(self, random_num, signature):
        val = "cvw" + struct.pack(">256I256I", random_num, signature)
        self.write(val)
        # removes AES encryption from the onion to make the RSA decryptable

    def onion_read(self):
        onion = struct.unpack(">256I", self.read(288))
        return onion

    # Puts the one-layer onion (still has inner RSA layer) in the AES channel to send to bank.
    def onion_write(self, outer_layer, signature):
        val = "own" + struct.pack(">512I256I", outer_layer, signature)
        self.write(val)

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    def _push_msg(self, msg):
        """Sends formatted message to PSoC

        Args:
            msg (str): message to be sent to the PSoC
        """
        pkt = struct.pack("B%ds" % (len(msg)), len(msg), msg)
        self.ser.write(pkt)
        time.sleep(0.1)

    def _pull_msg(self):
        """Pulls message form the PSoC

        Returns:
            string with message from PSoC
        """
        hdr = self.ser.read(1)
        if len(hdr) != 1:
            self._vp("RECEIVED BAD HEADER: \'%s\'" % hdr, logging.error)
            return ''
        pkt_len = struct.unpack('B', hdr)[0]
        return self.ser.read(pkt_len)

    def _sync(self, provision):
        """Synchronize communication with PSoC

        Raises:
            NotProvisioned if PSoC is unexpectedly unprovisioned
            AlreadyProvisioned if PSoC is unexpectedly already provisioned
        """
        if provision:
            if not self._sync_once(["CARD_P"]):
                self._vp("Already provisioned!", logging.error)
                raise AlreadyProvisioned
        else:
            if not self._sync_once(["CARD_N"]):
                self._vp("Not yet provisioned!", logging.error)
                raise NotProvisioned
        self._push_msg("GO\00")
        self._vp("Connection synced")

    def _sync_once(self, names):
        resp = ''
        while resp not in names:
            self._vp('Sending ready message')
            self._push_msg("READY\00")
            resp = self._pull_msg()
            self._vp('Got response \'%s\', want something from \'%s\'' % (resp, str(names)))

            # if in wrong state (provisioning/normal)
            if len(names) == 1 and resp != names[0] and resp[:-1] == names[0][:-1]:
                return False

        return resp

    def _authenticate(self, pin):
        """Requests authentication from the ATM card

        Args:
            pin (str): Challenge PIN

        Returns:
            bool: True if ATM card verified authentication, False otherwise
        """
        self._vp('Sending pin %s' % pin)
        self._push_msg(pin)

        resp = self._pull_msg()
        self._vp('Card response was %s' % resp)
        return resp == 'OK'

    def _get_uuid(self):
        """Retrieves the UUID from the ATM card

        Returns:
            str: UUID of ATM card
        """
        uuid = self._pull_msg()
        self._vp('Card sent UUID %s' % uuid)
        return uuid

    def _send_op(self, op):
        """Sends requested operation to ATM card

        Args:
            op (int): Operation to send from [self.CHECK_BAL, self.WITHDRAW,
                self.CHANGE_PIN]
        """
        self._vp('Sending op %d' % op)
        self._push_msg(str(op))

        while self._pull_msg() != 'K':
            self._vp('Card hasn\'t received op', logging.error)
        self._vp('Card received op')

    def change_pin(self, old_pin, new_pin):
        """Requests for a pin to be changed

        Args:
            old_pin (str): Challenge PIN
            new_pin (str): New PIN to change to

        Returns:
            bool: True if PIN was changed, False otherwise
        """
        self._sync(False)

        if not self._authenticate(old_pin):
            return False

        self._send_op(self.CHANGE_PIN)

        self._vp('Sending PIN %s' % new_pin)
        self._push_msg(new_pin)

        resp = self._pull_msg()
        self._vp('Card sent response %s' % resp)
        return resp == 'SUCCESS'

    def check_balance(self, pin):
        """Requests for a balance to be checked

        Args:
            pin (str): Challenge PIN

        Returns:
            str: UUID of ATM card on success
            bool: False if PIN didn't match
        """
        self._sync(False)

        if not self._authenticate(pin):
            return False

        self._send_op(self.CHECK_BAL)

        return self._get_uuid()

    def withdraw(self, pin):
        """Requests to withdraw from ATM

        Args:
            pin (str): Challenge PIN

        Returns:
            str: UUID of ATM card on success
            bool: False if PIN didn't match
        """
        self._sync(False)

        if not self._authenticate(pin):
            return False

        self._send_op(self.WITHDRAW)

        return self._get_uuid()

    def provision(self, card_num, private_outer_layer_key, public_inner_layer_key):
        """Attempts to provision a new ATM card

        Args:
            uuid (str): New UUID for ATM card
            pin (str): Initial PIN for ATM card

        Returns:
            bool: True if provisioning succeeded, False otherwise
        """
        self._sync(True)

        packet = "prv" + struct.pack(">32I256I256I", card_num, private_outer_layer_key, public_inner_layer_key)
        self.ser.write(packet)

        self._vp('Provisioning complete')

        return True

    def stupid_provision(self):
        return True
