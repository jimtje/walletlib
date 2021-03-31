from setuptools import setup, find_packages
import os

with open("requirements.txt") as f:
    requirements = f.read().splitlines()



setup(
    name="walletlib",
    version="0.2.1",
    packages=find_packages(),
    include_package_data=True,
    url="https://github.com/jimtje/walletlib",
    license="Unlicense",
    author="jim zhou",
    author_email="jimtje@gmail.com",
    description="Library for accessing cryptocurrency wallet files",
    requires_python=">=3.7.0",
    install_requires=["base58==2.1.0", "bsddb3==6.2.9", "coincurve==13.0.0", "Click==7.1.2", "pycryptodome==3.9.9"],
    entry_points={
        "console_scripts": ["dumpwallet = walletlib.scripts.dumpwallet:main"]
    },
)
