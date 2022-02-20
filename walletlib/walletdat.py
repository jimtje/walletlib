import collections
import datetime
import json
import socket
from typing import Dict, List, Optional

from bsddb3.db import *
from coincurve import PrivateKey, PublicKey
import base58
from .crypto import Crypter, doublesha256, doublesha256_checksum, ripemd160_sha256
from .exceptions import *
from .utils import BCDataStream, parse_CAddress, parse_BlockLocator, privkey_to_secret
import ipaddress


class Walletdat(object):
    def __init__(self, db: collections.OrderedDict) -> None:
        self.db_parsed = db
        self.keypairs = []
        self.rawkeys = []
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
        self.encrypted = False
        self.decrypted = True

    @classmethod
    def load(cls, filename):
        """

        :param filename: name of the file to load, file should be a BerkeleyDB Wallet.dat file
        :type filename: string
        :return: cls
        :rtype:Walletdat
        """
        try:
            db = DB()
            db.open(filename, "main", DB_BTREE, DB_THREAD | DB_RDONLY)
            coll = collections.OrderedDict((k, db[k]) for k in db.keys())
            return cls(coll)
        except (DBNoSuchFileError, DBError):
            raise DatabaseError(file=filename)

    def parse(self, passphrase: Optional[str] = None) -> None:
        """Parse the raw bytes of the db's contents. A bit of a mess right now so API likely to change

        :param passphrase: Passphrase to the wallet
        :type passphrase: string
        :return: None
        :rtype: None
        """
        for key, value in self.db_parsed.items():
            kds = BCDataStream(key)
            vds = BCDataStream(value)
            keytype = kds.read_string().decode()
            if keytype == "key":
                try:
                    keypair = KeyPair.parse_fromwallet(kds, vds)
                    self.keypairs.append(keypair)
                except KeypairError:
                    print(
                        "Error: Pubkey data doesn't match pubkey derived from private key"
                    )
            elif keytype == "wkey":
                keypair = KeyPair.parse_fromwallet(kds, vds)
                created = vds.read_int64()
                expires = vds.read_int64()
                comment = vds.read_string().decode()
                keypair.parse_wkeyinfo(created, expires, comment)
                self.keypairs.append(keypair)
            elif keytype == "keymeta":
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
                self.keymetas.append(
                        {
                            "version": version, "createtime": createtime, "hdkeypath": hdkeypath,
                            "hdmasterkey": hdmasterkey, "fingerprint": fingerprint, "has_keyorigin": has_keyorigin,
                        }
                )
                for key in self.keypairs:
                    if key.publickey == PublicKey(
                            pubkey).format(compressed=compressed):
                        key.set_keymeta(
                            version,
                            createtime,
                            hdkeypath,
                            hdmasterkey,
                            fingerprint,
                            has_keyorigin,
                        )
            elif keytype == "defaultkey":
                pk = vds.read_bytes(vds.read_compact_size())
                if len(pk) == 33:
                    self.defaultkey = PublicKey(pk).format()
                else:
                    self.defaultkey = PublicKey(pk).format(compressed=False)
            elif keytype == "name":
                if len(self.addressbook) > 0:
                    addr = kds.read_string().decode("utf-8")
                    if any(
                            item["address"] == addr for item in self.addressbook):
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
                if ord(base58.b58decode_check(addr)[:1]) == 5:
                    self.default_wifnetwork = 0
                else:
                    self.default_wifnetwork = ord(base58.b58decode_check(addr)[:1])
            elif type == "purpose":
                if len(self.addressbook) > 0:
                    addr = kds.read_string().decode("utf-8")
                    if any(
                            item["address"] == addr for item in self.addressbook):
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

            elif keytype == "tx":
                # todo: add segwit
                try:
                    txid = invert_txid(kds.read_bytes(32))
                    self.txes.append(Transaction.parse(txid, vds))
                except BaseException:
                    pass
            elif keytype == "hdchain":
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
            elif keytype == "version":
                self.version = vds.read_uint32()
            elif keytype == "minversion":
                self.minversion = vds.read_uint32()
            elif keytype == "setting":
                setname = kds.read_string().decode()
                if setname[0] == "f":
                    value = vds.read_boolean()
                elif setname == "addrIncoming":
                    value = str(ipaddress.ip_address(vds.read_bytes(4)))
                elif setname.startswith("addr"):
                    d = {"ip": "0.0.0.0", "port": 0, "nTime": 0}
                    try:
                        d["nVersion"] = vds.read_int32()
                        d["nTime"] = vds.read_uint32()
                        d["nServices"] = vds.read_uint64()
                        d["pchReserved"] = vds.read_bytes(12)
                        d["ip"] = str(ipaddress.ip_address(vds.read_bytes(4)))
                        d["port"] = vds.read_uint16()
                    except Exception:
                        pass
                    value = d
                elif setname == "nTransactionFee":
                    value = vds.read_int64()
                elif setname == "nLimitProcessors":
                    value = vds.read_int32()
                self.setting[setname] = value
            elif keytype == "bestblock":
                version = vds.read_int32()
                hashes = []
                for _ in range(vds.read_compact_size()):
                    hashes.append(vds.read_bytes(32).hex())
                self.bestblock = {"version": version, "hashes": hashes}
            elif keytype == "bestblock_nomerkle":
                version = vds.read_int32()
                hashes = []
                self.bestblock = {"version": version, "hashes": hashes}
            elif keytype == "pool":
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
            elif keytype == "destdata":
                publickey = kds.read_string().decode()
                key = kds.read_string().decode()
                # destination = vds.read_string().decode()
                self.destdata.append({"publickey": publickey, "key": key})
            elif keytype == "orderposnext":
                self.orderposnext = vds.read_int64()
            elif keytype == "flags":
                self.flags = vds.read_uint64()
            elif keytype == "mkey":
                nid = kds.read_uint32()
                encrypted_key = vds.read_string()
                salt = vds.read_string()
                derivationmethod = vds.read_uint32()
                derivationiters = vds.read_uint32()
                self.mkey = {
                    "nID": nid,
                    "encrypted_key": encrypted_key,
                    "salt": salt,
                    "derivationmethod": derivationmethod,
                    "derivationiterations": derivationiters,
                }
                self.encrypted = True

            elif keytype == "ckey":
                publickey = kds.read_bytes(kds.read_compact_size())
                encrypted_privkey = vds.read_bytes(vds.read_compact_size())
                self.rawkeys.append(
                    {"publickey": publickey, "encrypted_privkey": encrypted_privkey})
            else:
                print("{} type not implemented".format(type))
        if self.encrypted:
            if passphrase is not None:
                self.decrypter.keyfrompassphrase(
                    bytes(
                        passphrase,
                        "utf-8"),
                    self.mkey["salt"],
                    self.mkey["derivationiterations"],
                    self.mkey["derivationmethod"])
                masterkey = self.decrypter.decrypt(self.mkey["encrypted_key"])
                self.decrypter.SetKey(masterkey)
                for rawkey in self.rawkeys:
                    try:
                        self.decrypter.SetIV(doublesha256(rawkey["publickey"]))
                        dec = self.decrypter.decrypt(
                            rawkey["encrypted_privkey"])
                        self.keypairs.append(
                            KeyPair.parse_fromckey(
                                pubkey=rawkey["publickey"],
                                privkey=dec,
                                encryptedkey=rawkey["encrypted_privkey"],
                                crypted=False,
                            ))
                        self.decrypted = True

                    except BaseException:
                        raise PasswordError
            else:
                print("No passphrase set for encrypted wallet")
                self.decrypted = False
                for rawkey in self.rawkeys:
                    self.keypairs.append(
                        KeyPair.parse_fromckey(
                            pubkey=rawkey["publickey"],
                            privkey=None,
                            encryptedkey=rawkey["encrypted_privkey"],
                        )
                    )
        if self.default_wifnetwork is None:
            self.default_wifnetwork = 0


    def dump_keys(
        self,
        filepath: Optional[str] = None,
        version: Optional[int] = None,
        privkey_prefix_override: Optional[int] = None,
        compression_override: Optional[bool] = None,
    ) -> List:
        """ Dump just pubkey:privatekey either as a list, write to a file, or both.


        :param filepath: The output file. Leave as None to not write to file
        :type filepath:  string
        :param version: Version byte for the p2pkh key being generated. Should be between 0 and 127
        :type version:  int
        :param privkey_prefix_override: WIF Version bytes for secret. Should be between 128 and 255
        :type privkey_prefix_override: int
        :return: List of dicts with pubkey and privkey in bytesm or if not decrypted, pubkey and encrypted key
        :rtype: List
        :param compression_override: Compression setting for output keys, use None to automatically determine
        :type compression_override: bool
        """
        if len(self.keypairs) == 0 and self.db_parsed is not None:
            self.parse()
            # Run parse to populate if forgot
        output_list = []
        prefix = self.default_wifnetwork if version is None else version
        for keypair in self.keypairs:
            if privkey_prefix_override is not None:
                wif_prefix = privkey_prefix_override - 128
            else:
                wif_prefix = prefix
            pkey = keypair.pubkey_towif(prefix)
            if keypair.encryptedkey is None:
                if compression_override is not None:
                    priv = keypair.privkey_towif(
                        wif_prefix, compressed=compression_override
                    )
                else:
                    priv = keypair.privkey_towif(
                        wif_prefix, compressed=keypair.compressed)
                output_pair = {"public_key": pkey, "private_key": priv}
            else:
                output_pair = {"public_key": pkey,
                               "encrypted_privkey": keypair.encryptedkey.hex()}
            output_list.append(output_pair)
            if filepath is not None:
                with open(filepath, "a") as fq:
                    if "private_key" in output_pair:
                        fq.write(pkey.decode() + ":" + priv.decode() + "\n")
                    else:
                        fq.write(
                            pkey.decode() +
                            ":" +
                            keypair.encryptedkey.hex() +
                            "\n")

        return output_list

    def dump_all(
        self,
        filepath: Optional[str] = None,
        version: Optional[int] = None,
        privkey_prefix_override: Optional[int] = None,
    ) -> Dict:
        """ Dump all data from wallet

        :param filepath: The output file. Leave as None to not write to file
        :type filepath:  String
        :param version: Version byte for the p2pkh key being generated. Should be between 0 and 127
        :type version: Int
        :param privkey_prefix_override:  WIF Version byte override value just for the private key
        :type privkey_prefix_override: Int
        :return: A dict with the following key:values - keys: lists of dicts with compressed_private_key,
        public_key, uncompressed_private_key, label, created; pool: list of dicts with keys: n, nversion, ntime,
        publickey; tx: list of dicts with keys: txid, txin, txout, locktime; minversion, bestblock,
        default_network_version, orderposnext
        :rtype:
        """
        if len(self.keypairs) == 0 and self.db_parsed is not None:
            self.parse()

        structures = {
            "keys": [],
            "pool": [],
            "tx": [],
            "minversion": self.minversion,
            "version": self.version,
            "bestblock": self.bestblock,
            "default_network_version": self.default_wifnetwork,
            "orderposnext": self.orderposnext,
        }

        prefix = self.default_wifnetwork if version is None else version
        for keypair in self.keypairs:
            pkey = keypair.pubkey_towif(prefix)
            if keypair.encryptedkey is None:
                if privkey_prefix_override is not None:
                    wif_prefix = privkey_prefix_override - 128
                else:
                    wif_prefix = prefix
                priv_compressed = keypair.privkey_towif(
                    wif_prefix, compressed=True)
                priv_uncompressed = keypair.privkey_towif(
                    wif_prefix, compressed=False)
                keyd = {
                    "public_key": pkey.decode(),
                    "compressed_private_key": priv_compressed.decode(),
                    "uncompressed_private_key": priv_uncompressed.decode(),
                }
            else:
                priv_encrypted = keypair.encryptedkey.hex()
                keyd = {
                    "public_key": pkey.decode(),
                    "encrypted_private_key": priv_encrypted,
                }
            if len(self.addressbook) > 0:
                for a in self.addressbook:
                    if a["address"] == pkey.decode():
                        keyd["label"] = a["label"]
                        if "purpose" in a.keys():
                            keyd["purpose"] = a["purpose"]
            if keypair.createtime > 0:
                keyd["created"] = datetime.datetime.utcfromtimestamp(
                    keypair.createtime
                ).isoformat()
            structures["keys"].append(keyd)

        for tx in self.txes:
            apg = {
                "txid": tx.txid,
                "txin": tx.txin,
                "txout": tx.txout,
                "locktime": tx.locktime,
            }
            structures["tx"].append(apg)

        z = bytes([prefix])
        pools = [{
                    "n": p["n"],
                    "nversion": p["nversion"],
                    "ntime": datetime.datetime.utcfromtimestamp(
                        p["ntime"]).isoformat(),
                    "public_key": base58.b58encode_check(
                        z +
                        ripemd160_sha256(
                            p["publickey"])).decode(),
                } for p in self.pool]
        sorted(pools, key=lambda i: (i["n"], i["ntime"]))
        structures["pool"] = pools
        if self.defaultkey is not None:
            defkey = base58.b58encode_check(z + ripemd160_sha256(self.defaultkey)).decode()
            structures["default_key"] = defkey

        if filepath is not None:
            with open(filepath, "a") as fq:
                fq.write(json.dumps(structures, sort_keys=True, indent=4))
        return structures


class KeyPair(object):
    """Keypair object, should not be called directly


    """

    def __init__(
            self,
            rawkey,
            rawvalue,
            pubkey,
            sec,
            compressed,
            privkey=None,
            encryptedkey=None):
        self.rawkey = rawkey
        self.rawvalue = rawvalue
        self.publickey = pubkey
        self.privkey = privkey
        self.secret = sec
        self.version = None
        self.createtime = 0
        self.hdkeypath = None
        self.hdmasterkey = None
        self.compressed = compressed
        self.fingerprint = None
        self.has_keyorigin = False
        self.encryptedkey = encryptedkey
        self.expiretime = 0
        self.comment = ""

    @classmethod
    def parse_fromwallet(cls, kds, vds):
        """Class method to parse entry from wallet entry

        :param kds: BCDatastream object for keys
        :type kds: BCDataStream
        :param vds: BCDataStream object for values
        :type vds: BCDataStream
        :return: KeyPair
        :rtype: KeyPair
        """
        pubkeyraw = kds.read_bytes(kds.read_compact_size())
        privkeyraw = vds.read_bytes(vds.read_compact_size())
        if len(privkeyraw) == 279:
            sec = privkeyraw[9:41]
        else:
            sec = privkeyraw[8:40]
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
            raise KeypairError(
                message="Pubkey {} error".format(
                    pubkey.format(
                        compressed=compress).hex()))

    def parse_wkeyinfo(
            self,
            createtime: int,
            expiretime: int,
            comment: str) -> None:
        self.createtime = createtime
        self.expiretime = expiretime
        self.comment = comment

    @classmethod
    def parse_fromckey(cls, pubkey, privkey, encryptedkey, crypted=True):
        """Parse keypair from ckey (encrypted) values from wallet

        :param pubkey:
        :type pubkey:
        :param privkey:
        :type privkey:
        :param encryptedkey:
        :type encryptedkey:
        :param crypted:
        :type crypted:
        :return:
        :rtype:
        """
        pkey = PublicKey(pubkey)
        if len(pubkey) == 33:
            compress = True
        else:
            compress = False
        if crypted:
            return cls(
                rawkey=pubkey,
                rawvalue=None,
                pubkey=pkey.format(compressed=compress),
                sec=None,
                encryptedkey=encryptedkey,
                compressed=compress,
            )
        else:
            if len(privkey) == 279:
                sec = privkey[9:41]
            elif len(privkey) == 278:
                sec = privkey[8:40]
            else:
                sec = privkey
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
                    rawvalue=privkey,
                    pubkey=pubkey,
                    sec=sec,
                    encryptedkey=encryptedkey,
                    compressed=compress,
                    privkey=prkey
                )

    def set_keymeta(
        self,
        version: int,
        createtime: int,
        hdkeypath: Optional[str],
        hdmasterkey: Optional[str],
        fingerprint: int,
        has_keyorigin: bool = False,
    ) -> None:
        """Set keymeta field

        :param version: version parameter
        :type version: int
        :param createtime:created time
        :type createtime: int
        :param hdkeypath: hd key path
        :type hdkeypath: str
        :param hdmasterkey: hd master key
        :type hdmasterkey: str
        :param fingerprint: fingerprint value from wallet
        :type fingerprint: int
        :param has_keyorigin: whether has keyorigin field
        :type has_keyorigin: bool
        :return: None
        :rtype:
        """
        self.version = version
        self.createtime = createtime
        self.hdkeypath = hdkeypath
        self.hdmasterkey = hdmasterkey
        self.fingerprint = fingerprint
        self.has_keyorigin = has_keyorigin

    def pubkey_towif(self, network_version: int = 0) -> bytes:
        """

        :param network_version: version byte
        :type network_version: int
        :return:
        :rtype:
        """
        prefix = bytes([network_version])
        return base58.b58encode_check(
            prefix + ripemd160_sha256(self.publickey))

    def privkey_towif(self, network_version: int = 0,
                      compressed: bool = True) -> bytes:
        """

        :param network_version: version byte
        :type network_version: int
        :param compressed: whether the key is compressed
        :type compressed: bool
        :return:
        :rtype:
        """
        if self.privkey is not None:
            prefix = bytes([network_version + 128])
            if compressed:
                suffix = b"\x01"
            else:
                suffix = b""
            return base58.b58encode_check(
                prefix + self.privkey.secret + suffix)
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


def invert_txid(txid: bytes) -> str:
    """invert txid string from bytes

    :param txid: txid byte string from wallet
    :type txid: bytes
    :return: inverted txid string
    :rtype: str
    """
    tx = txid.hex()
    if len(tx) != 64:
        raise ValueError("txid %r length != 64" % tx)
    new_txid = ""
    for i in range(32):
        new_txid += tx[62 - 2 * i]
        new_txid += tx[62 - 2 * i + 1]
    return new_txid


class Transaction(object):
    """Transaction object - not to be called directly."""

    def __init__(
            self,
            txid: str,
            version: int,
            txin: List,
            txout: List,
            locktime: int,
            tx: bytes) -> None:
        """

        :param txid: transaction id string
        :type txid: str
        :param version: version byte
        :type version: int
        :param txin: txin list of dicts
        :type txin: list
        :param txout: txout list of dicts
        :type txout: list
        :param locktime: int
        :type locktime:
        :param tx: bytes
        :type tx:
        """
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
                "sequence": vds.read_uint32(),
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
        tx = vds.input[start: vds.read_cursor]
        return cls(
            txid,
            version,
            sorted(txin, key=lambda i: (i["prevout_n"], i["sequence"])),
            txout,
            locktime,
            tx,
        )
