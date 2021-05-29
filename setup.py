from setuptools import setup, find_packages
import os

with open("requirements.txt") as f:
    requirements = f.read().splitlines()


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="walletlib",
    version="0.2.4",
    packages=find_packages(),
    include_package_data=True,
    url="https://github.com/jimtje/walletlib",
    license="Unlicense",
    author="jim zhou",
    author_email="jimtje@gmail.com",
    description="Library for accessing cryptocurrency wallet files",
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='wallet crypto cryptocurrency',
    python_requires=">=3.7.0",
    install_requires=requirements,
    entry_points={
        "console_scripts": ["dumpwallet = walletlib.scripts.dumpwallet:main"]
    },
)
