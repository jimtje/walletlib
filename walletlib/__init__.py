"""
Library for accessing cryptocurrency wallet files

keywords: wallet, crypto, wallet.dat
author: jim zhou jimtje@gmail.com
"""

from .walletdat import Walletdat
from .protobufwallet import ProtobufWallet
__version__ = "0.2.10"

__url__ = "https://github.com/jimtje/walletlib"


__all__ = ["Walletdat", "ProtobufWallet"]
