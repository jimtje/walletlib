from Crypto.Cipher import AES
from typing import List, Union, Any, Optional, Dict
from pathlib import PurePath
from .bitcoinj_compat import *
import hashlib
import arrow
from coincurve import PrivateKey, PublicKey
import base58
import ipaddress
import json
import base64
from .crypto import ripemd160_sha256
from .exceptions import SerializationError, PasswordError
from hashlib import md5


class ProtobufWallet(object):

    def __init__(self, data: Any) -> None:
        self.raw_data = data
        self.wallet = Wallet()
        self.default_wifnetwork = 0
        self.keypairs = []
        self.description = ""
        self.pool = []
        self.txes = []
        self.mnemonics = []
        self.bestblock = {}
        self.tags = []
        self.extensions = []
        self.lastblockhash = None
        self.encryption_params = None
        self.encrypted = False

    @classmethod
    def load(cls, filename: Union[str, PurePath]):
        with open(filename, "rb") as d:
            data = d.read()
        if b'org.' in data:
            return cls(data)
        else:
            data = base64.b64decode(data)

        return cls(data)

    def parse(self, passphrase: Optional[str] = None):
        if self.raw_data[:8] == b'Salted__':
            if passphrase is None:
                raise PasswordError
            else:
                salt = self.raw_data[8:16]
                newdata = b''
                tmp2 = b''
                tmp = passphrase.encode() + salt
                while len(newdata) < 32 + AES.block_size:
                    msg = tmp2 + tmp
                    tmp2 = md5(msg).digest()
                    newdata += tmp2
                key = newdata[:32]
                iv = newdata[32:32 + AES.block_size]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                try:
                    padded_plain = cipher.decrypt(
                        self.raw_data[AES.block_size:])
                    pad_len = padded_plain[-1]
                    if isinstance(pad_len, str):
                        pad_len = ord(pad_len)
                    plain_data = padded_plain[:-pad_len]
                    self.wallet.parse(plain_data)
                except BaseException:
                    raise PasswordError
        else:
            self.wallet.parse(self.raw_data)

        if self.wallet.network_identifier == "org.dogecoin.production":
            self.default_wifnetwork = 30
        elif self.wallet.network_identifier == "org.bitcoin.production":
            self.default_wifnetwork = 0
        elif self.wallet.network_identifier == "org.litecoin.production":
            self.default_wifnetwork = 48
        elif self.wallet.network_identifier == "org.feathercoin.production":
            self.default_wifnetwork = 14
        else:
            self.default_wifnetwork = 0
            """
            Not sure what other variants have been made into bitcoinj-compatible
            """
        self.encryption_params = self.wallet.encryption_parameters.to_dict()
        if self.wallet.encryption_type > 1:
            self.encrypted = True
        if passphrase is None:
            for k in self.wallet.key:
                if k.type == 3:
                    mnemonic = k.secret_bytes.decode()
                    deterministic_seed = k.deterministic_seed.hex()
                    self.mnemonics.append(
                        {"mnemonic": mnemonic, "deterministic_seed": deterministic_seed})
                elif k.type == 4 or k.type == 1:
                    creation_timestamp = arrow.get(
                        int(k.creation_timestamp)).isoformat()
                    keydict = {"creation_timestamp": creation_timestamp}
                    if k.type == 4:
                        deterministic_key = k.deterministic_key.to_dict()
                        deterministic_key["chainCode"] = base64.b64decode(
                            deterministic_key['chainCode']).hex()
                        keydict["deterministic_key"] = deterministic_key
                    prefix = bytes([self.default_wifnetwork])
                    pubkey = base58.b58encode_check(
                        prefix + ripemd160_sha256(k.public_key)).decode()
                    keydict["pubkey"] = pubkey
                    if len(k.secret_bytes) > 0:
                        privkey_prefix = int.to_bytes(
                            self.default_wifnetwork + 128, 1, byteorder='big')
                        compressed = base58.b58encode_check(
                            privkey_prefix + k.secret_bytes).decode()
                        uncompressed = base58.b58encode_check(
                            privkey_prefix + k.secret_bytes + b'\x01').decode()
                        keydict["compressed_private_key"] = compressed
                        keydict["uncompressed_private_key"] = uncompressed
                    keydict["label"] = k.label
                    self.keypairs.append(keydict)

            if hasattr(self.wallet, 'lastSeenBlockHash'):
                self.lastblockhash = self.wallet.last_seen_block_hash.hex()
            if hasattr(self.wallet, 'transaction'):
                for t in self.wallet.transaction:
                    txjson = t.to_json()
                    print(txjson)
                    tx = t.to_dict()
                    tx["hash"] = base64.b64decode(tx['hash']).hex()
                    tx["updatedAt"] = arrow.get(
                        int(tx["updatedAt"])).isoformat()
                    txinputs = []
                    for txinput in tx['transactionInput']:
                        inputdict = {}
                        if 'transactionOutPointHash' in txinput.keys():
                            inputdict['transactionOutPointHash'] = base64.b64decode(
                                txinput['transactionOutPointHash']).hex()
                        if 'transactionOutPointIndex' in txinput.keys():
                            inputdict['transactionOutPointIndex'] = txinput['transactionOutPointIndex']
                        if 'scriptBytes' in txinput.keys():
                            inputdict['scriptBytes'] = base64.b64decode(
                                txinput['scriptBytes']).hex()
                        txinputs.append(inputdict)
                    tx['transactionInput'] = txinputs
                    txoutputs = []
                    for txoutput in tx['transactionOutput']:
                        outputdict = {}
                        if 'spentByTransactionHash' in txoutput.keys():
                            outputdict['spentByTransactionHash'] = base64.b64decode(
                                txoutput['spentByTransactionHash']).hex()
                        if 'spentByTransactionIndex' in txoutput.keys():
                            outputdict['spentByTransactionIndex'] = txoutput['spentByTransactionIndex']
                        if 'scriptBytes' in txoutput.keys():
                            outputdict['scriptBytes'] = base64.b64decode(
                                txoutput['scriptBytes']).hex()
                        if 'value' in txoutput.keys():
                            outputdict['value'] = txoutput['value']
                        txoutputs.append(outputdict)
                    tx['transactionOutput'] = txoutputs
                    bhashes = []
                    for bhash in tx['blockHash']:
                        bhashes.append(base64.b64decode(bhash).hex())
                    tx['blockHash'] = bhashes
                    self.txes.append(tx)
            self.description = self.wallet.description
            self.extensions = self.wallet.extension
            self.tags = self.wallet.tags
        else:
            self.keypairs = self.wallet.to_dict()['key']

    def dump_all(self, filepath: Optional[str] = None) -> Dict:
        output_items = {
            "keys": self.keypairs,
            "tx": self.txes,
            "mnemonics": self.mnemonics,
            "description": self.description}
        if filepath is not None:
            with open(filepath, "a") as ft:
                ft.write(json.dumps(output_items, sort_keys=True, indent=4))
        return output_items

    def dump_keys(self, filepath: Optional[str] = None) -> List:
        output_keys = list(self.mnemonics)
        output_keys.extend(iter(self.keypairs))
        if filepath is not None:
            with open(filepath, "a") as ft:
                ft.write(json.dumps(output_keys, sort_keys=True, indent=4))
        return output_keys
