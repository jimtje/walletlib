from Crypto.Cipher import AES
from typing import List, Union, Any, Optional
from pathlib import PurePath
from .bitcoinj_compat import *
import hashlib
import arrow

import base58
import base64
from .crypto import ripemd160_sha256
from .exceptions import SerializationError




class ProtobufWallet(object):

    def __init__(self, data: Any) -> None:
        self.wallet = Wallet()
        self.wallet.parse(data).to_dict()
        self.default_wifnetwork = 0
        self.keypairs = []
        self.pool = []
        self.txes = []
        self.mnemonics = []
        self.bestblock = {}
        self.lastblockhash = None




    @classmethod
    def load(cls, filename: Union[str, PurePath]):
        with open(filename, "rb") as d:
            data = d.read()
        if b'org.' in data:
            return cls(data)
        else:
            data = base64.b64decode(data)

        return cls(data)

    def parse(self, passphrase: Optional[str]=None):
        if self.wallet["networkIdentifier"] == "org.dogecoin.production":
            self.default_wifnetwork = 30
        elif self.wallet["networkIdentifier"] == "org.bitcoin.production":
            self.default_wifnetwork = 0
        elif self.wallet["networkIdentifier"] == "org.litecoin.production":
            self.default_wifnetwork = 48
        elif self.wallet["networkIdentifier"] == "org.feathercoin.production":
            self.default_wifnetwork = 14
        else:
            self.default_wifnetwork = 0
            """
            Not sure what other variants have been made into bitcoinj-compatible
            """
        if passphrase is None and len(self.wallet.key[0]["secretBytes"]):
            for k in self.wallet.key:
                prefix = bytes([self.default_wifnetwork + 128])
                compressed = base58.b58encode_check(prefix + base64.b64decode(k["secretBytes"])).decode()
                uncompressed = base58.b58encode_check(prefix + base64.b64decode(k["secretBytes"]) + b"\x01").decode()
                publickey = base58.b58encode_check(bytes[self.default_wifnetwork] + ripemd160_sha256(base64.b64decode(k["publicKey"]))).decode()
                creationtimestamp = arrow.get(k["creationTimestamp"]).format('YYYY-MM-DD HH:mm:ss ZZ')
                self.keypairs.append({"publickey": publickey, "uncompressed": uncompressed, "compressed": compressed, "created": creationtimestamp})
        else:
            for k in self.wallet.key:
                publickey = base58.b58encode_check(
                    bytes[self.default_wifnetwork] + ripemd160_sha256(base64.b64decode(k["publicKey"]))).decode()
                creationtimestamp = arrow.get(k["creationTimestamp"]).format('YYYY-MM-DD HH:mm:ss ZZ')
                encrypteddata = base64.b64decode(k["encryptedData"]["encryptedPrivateKey"]).hex()
                self.keypairs.append({"publickey": publickey, "encryptedkey": encrypteddata})






