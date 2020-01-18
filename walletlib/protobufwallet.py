from Crypto.Cipher import AES
from .bitcoinwallet_pb2 import *
import hashlib
import base64
from .crypto import keyivderivation, ripemd160_sha256
from .exceptions import PassphraseRequired, SerializationError
from coincurve import PrivateKey, PublicKey
import base58

class ProtobufWallet(object):

    def __init__(self, data):
        self.wallet = Wallet()
        self.wallet.ParseFromString(data)
        self.keypairs = []
        self.txes = []
        self.mnemonic = None
        if "dogecoin" in self.wallet.network_identifier:
            self.network_prefix = 30
        elif "litecoin" in self.wallet.network_identifier:
            self.network_prefix = 48
        else:
            self.network_prefix = 0

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
        for k in self.wallet.key:
            if k.type == 3 and len(k.secret_bytes) > 0:
                self.mnemonic = k.secret_bytes.decode()
            if k.type == 4 and len(k.public_key) > 0:
                pubkey = base58.b58encode_check(ripemd160_sha256(k.public_key))
                path = k.deterministic_key.path


class KeyPair(object):

    def __init__(self, pubkey, privkey, chaincode=None, path=None, created=None):
        self.pubkey = pubkey
        self.privkey = privkey
        self.chaincode = chaincode
        self.path = path
        self.created = created

    def pubkey_towif(self, network_version=0):
        prefix = bytes([network_version])
        return base58.b58encode_check(prefix + ripemd160_sha256(self.pubkey))

    def privkey_towif(self, network_version=0, compressed=False):
        prefix = bytes([network_version + 128])
        if compressed:
            suffix = b"\x01"
        else:
            suffix = b""
        return base58.b58encode_check(prefix + self.privkey + suffix)



















