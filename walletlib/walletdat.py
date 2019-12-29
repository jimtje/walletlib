import collections

from bsddb3.db import *
from .utils import *
from .exceptions import *
from Crypto.Cipher import AES
import datetime
import socket
import codecs
from typing import Dict, List, Tuple, Optional, TypeVar, Type
from coincurve import PrivateKey, PublicKey
from .crypto import *
import json



class Walletdat(object):
    def __init__(self, db: collections.OrderedDict) -> None:
        self.db_parsed = db
        self.keypairs = []
        self.pool = []
        self.txes = []
        self.keymetas = []
        self.defaultkey = None
        self.default_wifnetwork = None
        self.addressbook = []
        self.version = 0
        self.minversion = 0
        self.setting = {}
        self.hdchain = {}
        self.bestblock = {}
        self.destdata = []
        self.orderposnext = 0
        self.flags = 0
        self.decrypter = Crypter()
        self.mkey = None

    @classmethod
    def load(cls, filename):
        try:
            db = DB()
            db.open(filename, "main", DB_BTREE, DB_THREAD | DB_RDONLY)
            coll = collections.OrderedDict((k, db[k]) for k in db.keys())
            return cls(coll)
        except (DBNoSuchFileError, DBError):
            raise DatabaseError

    def parse(self, passphrase=None):
        for key, value in self.db_parsed.items():
            kds = BCDataStream(key)
            vds = BCDataStream(value)
            type = kds.read_string().decode()
            if type == "key":
                keypair = KeyPair.parse_fromwallet(kds, vds)
                self.keypairs.append(keypair)
            elif type == "wkey":
                keypair = KeyPair.parse_fromwallet(kds, vds)
                created = vds.read_int64()
                expires = vds.read_int64()
                comment = vds.read_string().decode()
                keypair.parse_wkeyinfo(created, expires, comment)
                self.keypairs.append(keypair)
            elif type == "keymeta":
                pubkey = kds.read_bytes(kds.read_compact_size())
                if len(pubkey) == 33:
                    compressed = True
                else:
                    compressed = False
                version = vds.read_int32()
                createtime = vds.read_int64()
                if version != 10:
                    hdkeypath = "No HD Key Found"
                    hdmasterkey = None
                else:
                    hdkeypath = vds.read_string().decode("utf-8")
                    hdmasterkey = vds.read_bytes(20).hex()
                if version != 12:
                    fingerprint = None
                    has_keyorigin = False
                else:
                    fingerprint = vds.read_uint32()
                    has_keyorigin = vds.read_boolean()
                if any(
                    k.publickey == PublicKey(pubkey).format(compressed=compressed)
                    for k in self.keypairs
                ):
                    for key in self.keypairs:
                        if key.publickey == PublicKey(pubkey).format(
                            compressed=compressed
                        ):
                            key.set_keymeta(
                                version,
                                createtime,
                                hdkeypath,
                                hdmasterkey,
                                fingerprint,
                                has_keyorigin,
                            )
                else:
                    self.keymetas.append(
                        {
                            "version": version,
                            "createtime": createtime,
                            "hdkeypath": hdkeypath,
                            "hdmasterkey": hdmasterkey,
                            "fingerprint": fingerprint,
                            "has_keyorigin": has_keyorigin,
                        }
                    )
            elif type == "defaultkey":
                pk = vds.read_bytes(vds.read_compact_size())
                if len(pk) == 33:
                    self.defaultkey = PublicKey(pk).format()
                else:
                    self.defaultkey = PublicKey(pk).format(compressed=False)
            elif type == "name":
                if len(self.addressbook) > 0:
                    addr = kds.read_string().decode("utf-8")
                    if any(item["address"] == addr for item in self.addressbook):
                        for item in self.addressbook:
                            if item["address"] == addr:
                                item.update(
                                    {"label": vds.read_string().decode("utf-8")}
                                )
                    else:
                        self.addressbook.append(
                            {
                                "address": addr,
                                "label": vds.read_string().decode("utf-8"),
                            }
                        )
                else:
                    addr = kds.read_string().decode("utf-8")
                    self.addressbook.append(
                        {"address": addr, "label": vds.read_string().decode("utf-8")}
                    )
                self.default_wifnetwork = ord(b58decode_check(addr)[:1])
            elif type == "purpose":
                if len(self.addressbook) > 0:
                    addr = kds.read_string().decode("utf-8")
                    if any(item["address"] == addr for item in self.addressbook):
                        for item in self.addressbook:
                            if item["address"] == addr:
                                item.update(
                                    {"purpose": vds.read_string().decode("utf-8")}
                                )
                    else:
                        self.addressbook.append(
                            {
                                "address": addr,
                                "purpose": vds.read_string().decode("utf-8"),
                            }
                        )
                else:
                    addr = kds.read_string().decode("utf-8")
                    self.addressbook.append(
                        {"address": addr, "purpose": vds.read_string().decode("utf-8")}
                    )

            elif type == "tx":
                # todo: add segwit
                try:
                    txid = invert_txid(kds.read_bytes(32))
                    self.txes.append(Transaction.parse(txid, vds))
                except:
                    pass
            elif type == "hdchain":
                version = vds.read_uint32()
                chain_counter = vds.read_uint32()
                master_keyid = vds.read_bytes(20).hex()
                self.hdchain = {
                    "version": version,
                    "chain_counter": chain_counter,
                    "master_keyid": master_keyid,
                }
                if version > 2:
                    self.hdchain["internal_counter"] = vds.read_uint32()
            elif type == "version":
                self.version = vds.read_uint32()
            elif type == "minversion":
                self.minversion = vds.read_uint32()
            elif type == "setting":
                setname = kds.read_string().decode()
                if setname[0] == "f":
                    value = vds.read_boolean()
                elif setname == "addrIncoming":
                    value = vds.read_string().hex()
                elif setname.startswith("addr"):
                    d = {"ip": "0.0.0.0", "port": 0, "nTime": 0}
                    try:
                        d["nVersion"] = vds.read_int32()
                        d["nTime"] = vds.read_uint32()
                        d["nServices"] = vds.read_uint64()
                        d["pchReserved"] = vds.read_bytes(12)
                        d["ip"] = socket.inet_ntoa(vds.read_bytes(4))
                        d["port"] = vds.read_uint16()
                    except:
                        pass
                    value = d
                elif setname == "nTransactionFee":
                    value = vds.read_int64()
                elif setname == "nLimitProcessors":
                    value = vds.read_int32()
                self.setting[setname] = value
            elif type == "bestblock":
                version = vds.read_int32()
                hashes = []
                for _ in range(vds.read_compact_size()):
                    hashes.append(vds.read_bytes(32).hex())
                self.bestblock = {"version": version, "hashes": hashes}
            elif type == "bestblock_nomerkle":
                version = vds.read_int32()
                hashes = []
                self.bestblock = {"version": version, "hashes": hashes}
            elif type == "pool":
                n = kds.read_int64()
                nversion = vds.read_int32()
                ntime = vds.read_int64()
                pubkey = vds.read_bytes(vds.read_compact_size())
                if len(pubkey) == 33:
                    compressed = True
                else:
                    compressed = False
                self.pool.append(
                    {
                        "n": n,
                        "nversion": nversion,
                        "ntime": ntime,
                        "publickey": PublicKey(pubkey).format(compressed=compressed),
                    }
                )
            elif type == "destdata":
                publickey = kds.read_string().decode()
                key = kds.read_string().decode()
                # destination = vds.read_string().decode()
                self.destdata.append({"publickey": publickey, "key": key})
            elif type == "orderposnext":
                self.orderposnext = vds.read_int64()
            elif type == "flags":
                self.flags = vds.read_uint64()
            elif type == "mkey":
                nid = kds.read_uint32()
                encrypted_key = vds.read_string()
                salt = vds.read_string()
                derivationmethod = vds.read_uint32()
                derivationiters = vds.read_uint32()
                self.mkey = {
                    "nID": nid,
                    "encrypted_key": encrypted_key.hex(),
                    "salt": salt.hex(),
                    "derivationmethod": derivationmethod,
                    "derivationiterations": derivationiters,
                }
                if passphrase is not None:
                    self.decrypter.keyfrompassphrase(
                        encrypted_key.hex(),
                        salt.hex(),
                        derivationiters,
                        derivationmethod,
                    )
                    masterkey = self.decrypter.decrypt(encrypted_key)
                    self.decrypter.setkey(masterkey)
                else:
                    print("No passphrase set for encrypted wallet")
            elif type == "ckey":
                publickey = kds.read_bytes(kds.read_compact_size())
                encrypted_privkey = vds.read_bytes(vds.read_compact_size())
                if passphrase is not None:
                    self.decrypter.setiv(doublesha256(publickey))
                    dec = self.decrypter.decrypt(encrypted_privkey)
                    self.keypairs.append(
                        KeyPair.parse_fromckey(
                            pubkey=publickey,
                            privkey=dec,
                            encryptedkey=encrypted_privkey,
                            crypted=False,
                        )
                    )
                else:
                    self.keypairs.append(
                        KeyPair.parse_fromckey(
                            pubkey=publickey,
                            privkey=None,
                            encryptedkey=encrypted_privkey,
                            crypted=True,
                        )
                    )

    def dump_keys(self, filepath=None, version=None):
        output_list = []
        if version is None:
            prefix = self.default_wifnetwork
        else:
            prefix = version

        for keypair in self.keypairs:
            pkey = keypair.pubkey_towif(prefix)
            priv = keypair.privkey_towif(prefix, compressed=keypair.compressed)
            output_list.append({"public_key": pkey, "private_key": priv})
            if filepath is not None:
                with open(filepath, "a") as fq:
                    fq.write(pkey.decode() + ":" + priv.decode() + "\n")
        return output_list

    def dump_all(self, filepath=None, version=None):

        structures = {
            "keys": [],
            "pool": [],
            "tx": [],
            "minversion": self.minversion,
            "version": self.version,
            "bestblock": self.bestblock,
            "default_network_version": self.default_wifnetwork,
        }
        if version is None:
            prefix = self.default_wifnetwork
        else:
            prefix = version

        for keypair in self.keypairs:
            pkey = keypair.pubkey_towif(prefix)
            priv_compressed = keypair.privkey_towif(prefix, compressed=True)
            priv_uncompressed = keypair.privkey_towif(prefix, compressed=False)
            keyd = {
                "public_key": pkey.decode(),
                "compressed_private_key": priv_compressed.decode(),
                "uncompressed_private_key": priv_uncompressed.decode(),
            }
            structures["keys"].append(keyd)

        for tx in self.txes:
            apg = {
                "txid": tx.txid,
                "txin": tx.txin,
                "txout": tx.txout,
                "locktime": tx.locktime,
            }
            structures["tx"].append(apg)

        for p in self.pool:
            z = bytes([prefix])
            structures["pool"].append(
                {
                    "n": p["n"],
                    "nversion": p["nversion"],
                    "ntime": datetime.datetime.utcfromtimestamp(p["ntime"]).isoformat(),
                    "public_key": b58encode_check(
                        z + ripemd160_sha256(p["publickey"])
                    ).decode(),
                }
            )

        if filepath is not None:
            with open(filepath, "a") as fq:
                fq.write(json.dumps(structures, sort_keys=True, indent=4))
        return structures


class KeyPair(object):
    def __init__(
        self, rawkey, rawvalue, pubkey, sec, compressed, privkey=None, encryptedkey=None
    ):
        self.rawkey = rawkey
        self.rawvalue = rawvalue
        self.publickey = pubkey
        self.privkey = privkey
        self.secret = sec
        self.version = None
        self.createtime = None
        self.hdkeypath = None
        self.hdmasterkey = None
        self.compressed = compressed
        self.fingerprint = None
        self.has_keyorigin = False
        self.encryptedkey = encryptedkey
        self.expiretime = None
        self.comment = ""

    @classmethod
    def parse_fromwallet(cls, kds, vds):
        pubkeyraw = kds.read_bytes(kds.read_compact_size())
        privkeyraw = vds.read_bytes(vds.read_compact_size())
        if len(privkeyraw) == 279:
            sec = privkeyraw[9 : 9 + 32]
        else:
            sec = privkeyraw[8 : 8 + 32]
        privkey = PrivateKey(sec)
        pubkey = PublicKey(pubkeyraw)
        if len(pubkeyraw) == 33:
            compress = True
        else:
            compress = False
        if pubkey == privkey.public_key:
            pubkey = privkey.public_key.format(compressed=compress)
            return cls(
                rawkey=pubkeyraw,
                rawvalue=privkeyraw,
                pubkey=pubkey,
                privkey=privkey,
                sec=sec,
                compressed=compress,
            )
        else:
            raise KeypairError

    def parse_wkeyinfo(self, createtime, expiretime, comment):
        self.createtime = createtime
        self.expiretime = expiretime
        self.comment = comment

    @classmethod
    def parse_fromckey(cls, pubkey, privkey, encryptedkey, crypted=True):
        pkey = PublicKey(pubkey)
        if len(pubkey) == 33:
            compress = True
        else:
            compress = False
        if crypted:
            return cls(
                rawkey=pubkey,
                rawvalue=None,
                pubkey=pkey,
                privkey=None,
                sec=None,
                encryptedkey=encryptedkey,
                compressed=compress,
            )
        else:
            if len(privkey) == 279:
                sec = privkey[9 : 9 + 32]
            else:
                sec = privkey[8 : 8 + 32]
            prkey = PrivateKey(sec)
            if pkey == prkey.public_key:
                pkey = prkey.public_key.format(compressed=compress)
                return cls(
                    rawkey=pubkey,
                    rawvalue=privkey,
                    pubkey=pkey,
                    privkey=prkey,
                    sec=sec,
                    compressed=compress,
                )
            else:
                print("Wrong decryption password")
                return cls(
                    rawkey=pubkey,
                    rawvalue=None,
                    pubkey=pkey,
                    privkey=None,
                    sec=None,
                    encryptedkey=encryptedkey,
                    compressed=compress,
                )

    def set_keymeta(
        self,
        version,
        createtime,
        hdkeypath,
        hdmasterkey,
        fingerprint,
        has_keyorigin=False,
    ):
        self.version = version
        self.createtime = createtime
        self.hdkeypath = hdkeypath
        self.hdmasterkey = hdmasterkey
        self.fingerprint = fingerprint
        self.has_keyorigin = has_keyorigin

    def pubkey_towif(self, network_version=0):
        prefix = bytes([network_version])
        return b58encode_check(prefix + ripemd160_sha256(self.publickey))

    def privkey_towif(self, network_version=0, compressed=True):
        if self.privkey is not None:
            prefix = bytes([network_version + 128])
            if compressed:
                suffix = b"\x01"
            else:
                suffix = b""
            return b58encode_check(prefix + self.privkey.secret + suffix)
        elif self.encryptedkey is not None:
            return self.encryptedkey

    def __repl__(self):
        if self.privkey is None and self.encryptedkey is not None:
            return "Pubkey: {} Encrypted Privkey: {}".format(
                self.publickey.hex(), self.encryptedkey.hex()
            )
        elif self.privkey is not None and self.encryptedkey is None:
            return "Pubkey: {} Privkey: {}".format(
                self.publickey.hex(), self.privkey.hex()
            )
        else:
            return "Pubkey: {}".format(self.publickey.hex())


def invert_txid(txid):
    tx = txid.hex()
    if len(tx) != 64:
        raise ValueError("txid %r length != 64" % tx)
    new_txid = ""
    for i in range(32):
        new_txid += tx[62 - 2 * i]
        new_txid += tx[62 - 2 * i + 1]
    return new_txid


class Transaction(object):
    def __init__(self, txid, version, txin, txout, locktime, tx):
        self.txid = txid
        self.version = version
        self.txin = txin
        self.txout = txout
        self.locktime = locktime
        self.tx = tx

    @classmethod
    def parse(cls, txid, vds):
        start = vds.read_cursor
        version = vds.read_int32()
        n_vin = vds.read_compact_size()
        txin = []
        for _ in range(n_vin):
            d = {
                "prevout_hash": vds.read_bytes(32).hex(),
                "prevout_n": vds.read_uint32(),
                "scriptSig": vds.read_bytes(vds.read_compact_size()).hex(),
                "sequence": vds.read_uint32()
            }
            txin.append(d)
        n_vout = vds.read_compact_size()
        txout = []
        for _ in range(n_vout):
            d = {
                "value": vds.read_int64() / 1e8,
                "scriptPubKey": vds.read_bytes(vds.read_compact_size()).hex(),
            }
            txout.append(d)
        locktime = vds.read_uint32()
        tx = vds.input[start : vds.read_cursor]
        return cls(txid, version, txin, txout, locktime, tx)

