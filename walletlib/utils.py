import struct
import socket
from .exceptions import *


class BCDataStream(object):
    """BCDataStream from pywallet"""

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
            result = self.input[self.read_cursor: self.read_cursor + length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

    def read_boolean(self):
        return self.read_bytes(1)[0] != chr(0)

    def read_int16(self):
        return self._read_num("<h")

    def read_uint16(self):
        return self._read_num("<H")

    def read_int32(self):
        return self._read_num("<i")

    def read_uint32(self):
        return self._read_num("<I")

    def read_int64(self):
        return self._read_num("<q")

    def read_uint64(self):
        return self._read_num("<Q")

    def read_uint256(self):
        r = 0
        for i in range(8):
            t = struct.unpack("<I", self.read_bytes(4))[0]
            r += t << (i * 32)
        return r

    def read_vector(self, f):
        nit = self.read_compact_size()
        r = []
        for _ in range(nit):
            t = f()
            t.deserialize(self)
            r.append(t)
        return r

    def read_compact_size(self):
        size = int(self.input[self.read_cursor])
        self.read_cursor += 1
        if size == 253:
            size = self._read_num("<H")
        elif size == 254:
            size = self._read_num("<I")
        elif size == 255:
            size = self._read_num("<Q")
        return size

    def _read_num(self, format):
        (i,) = struct.unpack_from(format, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(format)
        return i

    def get_onebyte(self):
        byte = self.read_bytes(1)
        self.read_cursor -= 1
        return byte


def parse_CAddress(vds):
    d = {"ip": "0.0.0.0", "port": 0, "nTime": 0}
    try:
        d["nVersion"] = vds.read_int32()
        d["nTime"] = vds.read_uint32()
        d["nServices"] = vds.read_uint64()
        d["pchReserved"] = vds.read_bytes(12)
        d["ip"] = socket.inet_ntoa(vds.read_bytes(4))
        d["port"] = vds.read_uint16()
    except BaseException:
        pass
    return d


def parse_BlockLocator(vds):
    d = {"hashes": []}
    nHashes = vds.read_compact_size()
    for i in range(nHashes):
        d["hashes"].append(vds.read_bytes(32))
    return d


def privkey_to_secret(privkey: bytes) -> bytes:
    if len(privkey) == 279:
        return privkey[9:41]
    else:
        return privkey[8:40]
