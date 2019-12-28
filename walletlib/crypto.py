import hashlib
from Crypto.Cipher import AES


def doublesha256(bytestring):
    return hashlib.sha256(hashlib.sha256(bytestring).digest()).digest()


def doublesha256_checksum(bytestring):
    return doublesha256(bytestring)[:4]


def ripemd160_sha256(key):
    return hashlib.new("ripemd160", hashlib.sha256(key).digest()).digest()


class Crypter(object):

    def __init__(self):
        self.chkey = None
        self.chiv = None

    def setkey(self, key):
        self.chkey = key

    def setiv(self, iv):
        self.chiv = iv

    def keyfrompassphrase(self, keydata, salt, deriviters, derivmethod):
        if derivmethod != 0:
            return 0
        data = keydata + salt
        for _ in range(deriviters):
            data = hashlib.sha512(data).digest()
        self.setkey(data[:32])
        self.setiv(data[32:32+16])
        return len(data)

    def encrypt(self, data):
        return AES.new(self.chkey, AES.MODE_CBC, self.chiv).encrypt(data)[:32]

    def decrypt(self, data):
        return AES.new(self.chkey, AES.MODE_CBC, self.chiv).decrypt(data)[:32]




