import struct
import base58
import hashlib
import binascii
import socket
from .exceptions import *


class BCDataStream(object):
    def __init__(self, input):
        self.input = bytes(input)
        self.read_cursor = 0

    def read_string(self):
        # Strings are encoded depending on length:
        # 0 to 252 :	1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        try:
            length = self.read_compact_size()
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return self.read_bytes(length)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor + length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

    def read_boolean(self):
        return self.read_bytes(1)[0] != chr(0)

    def read_int16(self):
        return self._read_num('<h')

    def read_uint16(self):
        return self._read_num('<H')

    def read_int32(self):
        return self._read_num('<i')

    def read_uint32(self):
        return self._read_num('<I')

    def read_int64(self):
        return self._read_num('<q')

    def read_uint64(self):
        return self._read_num('<Q')

    def read_compact_size(self):
        size = int(self.input[self.read_cursor])
        self.read_cursor += 1
        if size == 253:
            size = self._read_num('<H')
        elif size == 254:
            size = self._read_num('<I')
        elif size == 255:
            size = self._read_num('<Q')
        return size

    def _read_num(self, format):
        (i,) = struct.unpack_from(format, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(format)
        return i

def parse_TxIn(vds):
    d = {}
    d['prevout_hash'] = vds.read_bytes(32)
    d['prevout_n'] = vds.read_uint32()
    d['scriptSig'] = vds.read_bytes(vds.read_compact_size())
    d['sequence'] = vds.read_uint32()
    return d


def parse_TxOut(vds):
    d = {}
    d['value'] = vds.read_int64() / 1e8
    d['scriptPubKey'] = vds.read_bytes(vds.read_compact_size())
    return d


def inversetxid(txid):
    txid = binascii.hexlify(txid).decode()
    if len(txid) != 64:
        raise ValueError('txid %r length != 64' % txid)
    new_txid = ""
    for i in range(32):
        new_txid += txid[62 - 2 * i]
        new_txid += txid[62 - 2 * i + 1]
    return new_txid


def parse_CAddress(vds):
    d = {'ip': '0.0.0.0', 'port': 0, 'nTime': 0}
    try:
        d['nVersion'] = vds.read_int32()
        d['nTime'] = vds.read_uint32()
        d['nServices'] = vds.read_uint64()
        d['pchReserved'] = vds.read_bytes(12)
        d['ip'] = socket.inet_ntoa(vds.read_bytes(4))
        d['port'] = vds.read_uint16()
    except:
        pass
    return d


def parse_BlockLocator(vds):
    d = {'hashes': []}
    nHashes = vds.read_compact_size()
    for i in range(nHashes):
        d['hashes'].append(vds.read_bytes(32))
    return d


def parse_setting(setting, vds):
    if setting[0] == "f":  # flag (boolean) settings
        return str(vds.read_boolean())
    elif setting[0:4] == "addr":  # CAddress
        return parse_CAddress(vds)
    elif setting == "nTransactionFee":
        return vds.read_int64()
    elif setting == "nLimitProcessors":
        return vds.read_int32()
    return {'unknown': vds}

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def encode_base58_check(secret):
    hash = double_sha256(secret)
    return base58.b58encode(secret + hash[0:4])


def privkey_to_secret(privkey):
    if len(privkey) == 279:
        return privkey[9:9 + 32]
    else:
        return privkey[8:8 + 32]


def secret_to_asecret(secret, version):
    prefix = (version + 128) & 255
    vchIn = bytes([prefix]) + secret
    return encode_base58_check(vchIn)


def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()


def public_key_to_bc_address(public_key, version):
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, version)


def hash_160_to_bc_address(h160, version):
    vh160 = bytes([int(version)]) + h160
    h = double_sha256(vh160)
    addr = vh160 + h[0:4]
    return base58.b58encode(addr)


def bc_address_to_hash_160(addr):
    bytes = base58.b58decode(addr, 25)
    return bytes[1:21]
