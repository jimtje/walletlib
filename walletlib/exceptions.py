class WalletDatError(Exception):

    def __init__(self, file=None, message=None):
        if message is None:
            message = "Error processing {}".format(file)
        super(WalletDatError, self).__init__(message)
        self.file = file


class SerializationError(WalletDatError):
    pass


class DatabaseError(WalletDatError):
    pass


class KeypairError(WalletDatError):
    pass


class PasswordError(WalletDatError):
    pass
