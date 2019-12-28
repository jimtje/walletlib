class WalletDatError(Exception):
    pass

class SerializationError(WalletDatError):
    pass

class DatabaseError(WalletDatError):
    pass

class KeypairError(WalletDatError):
    pass
