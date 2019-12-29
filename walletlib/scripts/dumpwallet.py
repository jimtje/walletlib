#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CLI Interface to Walletlib

This is a simple implementation to allow walletlib to be used from the cli.
It will certainly gain more features as they are added. Currently it takes a wallet.dat file and dumps either a full
seet of its contents or just the keys out.

"""
import click
from walletlib import Walletdat


@click.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option("-p", "--password", help="Password if any")
@click.option(
    "-o", "--output", help="File to save to. If not set, results only will be displayed"
)
@click.option(
    "-v",
    "--versionprefix",
    type=int,
    help="Force output to use this p2pkh version byte",
)
@click.option(
    "-s", "--secretprefix", type=int, help="Force output to use this WIF version byte"
)
@click.option("--keys", is_flag=True, help="Only dump keys.")
def main(filename, password, output, versionprefix, secretprefix, keys):
    w = Walletdat.load(filename)
    click.echo("Loaded file")
    if password:
        w.parse(passphrase=password)
    else:
        w.parse()
    click.echo(
        "Found {} keypairs and {} transactions".format(len(w.keypairs), len(w.txes))
    )
    if keys:
        w.dump_keys(output, version=versionprefix, privkey_prefix_override=secretprefix)
    else:
        w.dump_all(output, version=versionprefix, privkey_prefix_override=secretprefix)
    click.echo("Done")


