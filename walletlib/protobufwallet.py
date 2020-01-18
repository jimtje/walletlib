from Crypto.Cipher import AES
from .bitcoinwallet_pb2 import *
import hashlib
import base64
from .crypto import keyivderivation
from .exceptions import PassphraseRequired, SerializationError


class ProtobufWallet(object):

    def __init__(self, data):
        self.wallet = Wallet()
        self.wallet.ParseFromString(data)
        self.default_wifnetwork = 0
        self.keypairs = []
        self.pool = []
        self.txes = []
        self.mnemonics = []
        self.bestblock = {}



    @classmethod
    def load(cls, filename, passphrase=None):
        with open(filename, "rb") as d:
            data = d.read()
        if b'org.' in data:
            return cls(data)
        else:
            data = base64.b64decode(data)

        if data[:8] == b'Salted__':
            if passphrase is not None:
                salt = data[8:16]
                key, iv = keyivderivation(passphrase, salt, 32, AES.block_size)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plaintext = cipher.decrypt(data[AES.block_size:])
                if isinstance(plaintext[-1], str):
                    padding_length = ord(plaintext[-1])
                else:
                    padding_length = plaintext[-1]
                return cls(plaintext[:padding_length])
            else:
                raise PassphraseRequired(message="Passphrase required, but was not supplied")
        else:
            raise SerializationError(message="Invalid wallet data")

    def parse(self):
        if "dogecoin" in self.w.network_identifier:











