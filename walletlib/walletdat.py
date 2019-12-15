import collections

from bsddb3.db import *

from .exceptions import *


class WalletDat(object):

    def __init__(self):
        self.db = DB()
        self.dbraw = None

    def load(self, file):
        try:
            self.db.open(file, "main", DB_BTREE, DB_RDONLY)
            self.dbraw = collections.OrderedDict((k, self.db[k]) for k in self.db.keys())
        except (DB_NOTFOUND, DB_PAGE_NOTFOUND):
            raise DatabaseError




