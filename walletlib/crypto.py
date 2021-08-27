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
        self.chKey = None
        self.chIV = None

    @staticmethod
    def append_PKCS7_padding(s):
        """return s padded to a multiple of 16-bytes by PKCS7 padding"""
        numpads = 16 - (len(s) % 16)
        return s + numpads * chr(numpads)

    def keyfrompassphrase(
        self, vKeyData, vSalt, nDerivIterations, nDerivationMethod
    ):
        if nDerivationMethod != 0:
            return 0
        data = vKeyData + vSalt
        for i in range(nDerivIterations):
            data = hashlib.sha512(data).digest()
        self.SetKey(data[0:32])
        self.SetIV(data[32: 32 + 16])
        return len(data)

    def SetKey(self, key):
        self.chKey = key

    def SetIV(self, iv):
        self.chIV = iv[0:16]

    def encrypt(self, data):
        return AES.new(self.chKey, AES.MODE_CBC, self.chIV).encrypt(
            Crypter.append_PKCS7_padding(data)
        )

    def decrypt(self, data):
        return AES.new(self.chKey, AES.MODE_CBC, self.chIV).decrypt(data)[0:32]
