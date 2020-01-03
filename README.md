# walletlib
![PyPI - Python Version](https://img.shields.io/badge/python-3.6%20%7C%203.7%20%7C%203.8-blue)

Unified interface to programmatically open and extract data from cryptocurrency wallet backup files

## Quick Start
This module requires Python 3.6+

```bash
$ pip install walletlib
```
A convenient cli script is available after installation.
```bash
$ python -m dumpwallet wallet.dat -o output.txt
```

## Features
- Automatic reading of version byte and WIF prefix from default keys
- Dumping just keys or all data
- Read only access of wallet files

## Installation
The simplest way to install walletlib is using pip.
```bash
$ pip install walletlib
```
You can also clone this repo and then run
```bash
$ python setup.py install
```
## Usage
```python
import walletlib

wallet = walletlib.Walletdat.load("wallet.dat")
wallet.parse(passphrase="password")
wallet.dump_all(filepath="output.txt")
wallet.dump_keys(filepath="output_keys.txt")

```

## Roadmap
- [x] wallet.dat
  - [x] Encrypted keys
  - [x] p2pkh Wallets
  - [ ] Bech32 wallets
- [ ] Bitcoinj/Dogecoinj/Altcoinj wallets
- [ ] Blockchain.com wallet.aes.json
