import collections

from bsddb3.db import *
from .utils import *
from .exceptions import *
from Crypto.Cipher import AES
import datetime
import codecs


class Walletdat(object):
    def __init__(self):
        self.db = DB()
        self.dbraw = None
        self.dbparsed = None

    def load(self, file):
        try:
            self.db.open(file, "main", DB_BTREE, DB_RDONLY)
            self.dbraw = collections.OrderedDict(
                (k, self.db[k]) for k in self.db.keys()
            )
            self.dbparsed = []
            for key, value in self.dbraw.items():
                self.dbparsed.append(WalletItem.parse(key, value))
        except (DB_NOTFOUND, DB_PAGE_NOTFOUND):
            raise DatabaseError

    def dump(self, version=0, passphrase=None):
        """
        params:
        version: https://github.com/libbitcoin/libbitcoin-system/wiki/Altcoin-Version-Mappings - Mainnet version p2pkh prefix in int
        passphrase: passphrase
        """
        outdict = {
            "keys": {},
            "pool": [],
            "tx": [],
            "names": [],
            "ckey": [],
            "mkey": [],
            "purpose": [],
        }
        keydicts = {}
        for item in self.dbparsed:
            if item.type == "purpose":
                outdict["purpose"].append(
                    {
                        "pubkey": item.data["pubkey"].decode("utf-8"),
                        "purpose": item.data["purpose"].decode("utf-8"),
                    }
                )
            if item.type == "key":
                if "public_key" in item.data.keys():
                    public_key = public_key_to_bc_address(
                        item.data["public_key"], version=version
                    ).decode("utf-8")
                    if public_key not in keydicts.keys():
                        keydicts[public_key] = {}
                if "private_key" in item.data.keys():
                    keydicts[public_key]["private_key"] = secret_to_asecret(
                        privkey_to_secret(item.data["private_key"]), version=version
                    ).decode("utf-8")
            if item.type == "keymeta":
                public_key = public_key_to_bc_address(
                    item.data["public_key"], version=version
                ).decode("utf-8")
                keydicts[public_key]["keymeta_version"] = item.data["keymetaversion"]
                keydicts[public_key][
                    "keymeta_timestamp"
                ] = datetime.datetime.fromtimestamp(
                    item.data["keymetatimestamp"]
                ).strftime(
                    "%c"
                )
                if "keymetachain" in item.data.keys():
                    keydicts[public_key]["key_derivation"] = item.data["keymetachain"]
            if item.type == "name":
                outdict["names"].append(
                    {
                        "key": item.data["hash"].decode("utf-8"),
                        "value": item.data["name"].decode("utf-8"),
                    }
                )
            if item.type == "tx":
                outdict["tx"].append(
                    {
                        "tx_id": item.data["tx_id"],
                        "txin": item.data["txIn"],
                        "txout": item.data["txOut"],
                        "tx_v": item.data["txv"],
                        "tx_k": item.data["txk"],
                    }
                )
            if item.type == "version":
                outdict["version"] = item.data["version"]
            if item.type == "minversion":
                outdict["minversion"] = item.data["minversion"]
            if item.type == "setting":
                outdict["setting"][item.data["setting"]] = item.data["value"]
            if item.type == "defaultkey":
                outdict["defaultkey"] = public_key_to_bc_address(
                    item.data["key"], version
                ).decode("utf-8")
            if item.type == "pool":
                outdict["pool"].append(
                    {
                        "n": item.data["n"],
                        "addr": public_key_to_bc_address(
                            item.data["public_key"], version
                        ).decode("utf-8"),
                        "nTime": datetime.datetime.fromtimestamp(
                            item.data["nTime"]
                        ).strftime("%c"),
                        "nVersion": item.data["nVersion"],
                    }
                )
            if item.type == "bestblock":
                outdict["bestblock"] = codecs.encode(
                    item.data["hashes"][0][::-1], encoding="hex"
                ).decode("utf-8")
            if item.type == "mkey":
                if passphrase is not None:
                    decrypter = WalletdatDecrypter(
                        passphrase,
                        codecs.decode(item.data["salt"], encoding="hex"),
                        item.data["nDerivationIterations"],
                    )
                    mk = decrypter.decrypt(item.data["encrypted_key"])
                    decrypter.setKey(mk)
        outdict["keys"] = keydicts
        return outdict


class WalletdatDecrypter(object):
    def __init__(self, passphrase, salt, iter):
        self.data = passphrase + salt
        for i in range(iter):
            self.data = hashlib.sha512(self.data).digest()
        self.key = self.data[0:32]
        self.iv = self.data[32 : 32 + 16]

    def setKey(self, key):
        self.key = key

    def decrypt(self, data):
        return AES.new(self.key, AES.MODE_CBC, self.iv).decrypt(data)[0:32]


class WalletItem:
    item_type = None

    def __init__(self, key, value, type, data):
        self.key = key
        self.value = value
        self.type = type
        self.data = data

    def __repr__(self):
        return "<%s item: %s>" % (self.type, self.data)

    @classmethod
    def parse(cls, key, value):
        kds = BCDataStream(key)
        vds = BCDataStream(value)
        type = kds.read_string().decode()
        data = {}

        # From Pywallet:

        if type == "tx":
            data["tx_id"] = inversetxid(kds.read_bytes(32))
            start = vds.read_cursor
            data["version"] = vds.read_int32()
            n_vin = vds.read_compact_size()
            data["txIn"] = []
            for i in range(n_vin):
                data["txIn"].append(parse_TxIn(vds))
            n_vout = vds.read_compact_size()
            data["txOut"] = []
            for i in range(n_vout):
                data["txOut"].append(parse_TxOut(vds))
            data["lockTime"] = vds.read_uint32()
            data["tx"] = vds.input[start : vds.read_cursor]
            data["txv"] = value
            data["txk"] = key
        elif type == "name":
            data["hash"] = kds.read_string()
            data["name"] = vds.read_string()
        elif type == "version":
            data["version"] = vds.read_uint32()
        elif type == "minversion":
            data["minversion"] = vds.read_uint32()
        elif type == "setting":
            data["setting"] = kds.read_string()
            data["value"] = parse_setting(data["setting"].decode(), vds)
        elif type == "key":
            data["public_key"] = kds.read_bytes(kds.read_compact_size())
            data["private_key"] = vds.read_bytes(vds.read_compact_size())
        elif type == "wkey":
            data["public_key"] = kds.read_bytes(kds.read_compact_size())
            data["private_key"] = vds.read_bytes(vds.read_compact_size())
            data["created"] = vds.read_int64()
            data["expires"] = vds.read_int64()
            data["comment"] = vds.read_string()
        elif type == "defaultkey":
            data["key"] = vds.read_bytes(vds.read_compact_size())
        elif type == "pool":
            data["n"] = kds.read_int64()
            data["nVersion"] = vds.read_int32()
            data["nTime"] = vds.read_int64()
            data["public_key"] = vds.read_bytes(vds.read_compact_size())
        elif type == "acc":
            data["account"] = kds.read_string()
            data["nVersion"] = vds.read_int32()
            data["public_key"] = vds.read_bytes(vds.read_compact_size())
        elif type == "acentry":
            data["account"] = kds.read_string()
            data["n"] = kds.read_uint64()
            data["nVersion"] = vds.read_int32()
            data["nCreditDebit"] = vds.read_int64()
            data["nTime"] = vds.read_int64()
            data["otherAccount"] = vds.read_string()
            data["comment"] = vds.read_string()
        elif type == "bestblock":
            data["nVersion"] = vds.read_int32()
            data.update(parse_BlockLocator(vds))
        elif type == "bestblock_nomerkle":
            data["nVersion"] = vds.read_int32()
            data.update(parse_BlockLocator(vds))
        elif type == "ckey":
            data["public_key"] = kds.read_bytes(kds.read_compact_size())
            data["encrypted_private_key"] = vds.read_bytes(vds.read_compact_size())
        elif type == "mkey":
            data["nID"] = kds.read_uint32()
            data["encrypted_key"] = vds.read_string()
            data["salt"] = vds.read_string()
            data["nDerivationMethod"] = vds.read_uint32()
            data["nDerivationIterations"] = vds.read_uint32()
            data["otherParams"] = vds.read_string()
        elif type == "keymeta":
            data["public_key"] = kds.read_bytes(kds.read_compact_size())
            keymetaversion = vds.read_int32()
            data["keymetaversion"] = keymetaversion
            data["keymetatimestamp"] = vds.read_int64()
            if keymetaversion == 10:
                data["keymetachain"] = vds.read_string()
        elif type == "hdchain":
            data["hdchain_base"] = vds.read_uint32()
            data["hdchain_split"] = vds.read_uint32()
            data["hdchain"] = vds.read_bytes(vds.read_compact_size())
        elif type == "purpose":
            data["pubkey"] = kds.read_string()
            data["purpose"] = vds.read_string()
        else:
            print(type)

        for item_cls in cls.__subclasses__():
            if item_cls.item_type == type:
                break
        else:
            item_cls = cls

        return item_cls(key, value, type, data)


def parse_wallet_dict(wallet_dict):
    for key, value in wallet_dict.items():
        yield WalletItem.parse(key, value)
