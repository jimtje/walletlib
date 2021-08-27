#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CLI Interface to Walletlib

This is a simple implementation to allow walletlib to be used from the cli.
It will certainly gain more features as they are added. Currently it takes a wallet.dat file and dumps either a full
seet of its contents or just the keys out.

"""
import click
from walletlib import Walletdat, ProtobufWallet
import json


@click.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option("-p", "--password", help="Password if any", type=click.STRING)
@click.option("-o", "--output",
              help="File to save to. If not set, results only will be displayed")
@click.option(
    "-v",
    "--versionprefix",
    type=int,
    help="Force output to use this p2pkh version byte",
)
@click.option("-s", "--secretprefix", type=int,
              help="Force output to use this WIF version byte")
@click.option("--keys", is_flag=True, help="Only dump keys.")
def main(filename, password, output, versionprefix, secretprefix, keys):
    if filename.endswith(".dat"):
        w = Walletdat.load(filename)
        click.echo("Loaded file")
        if password:
            w.parse(passphrase=str(password))
        else:
            w.parse()
        click.echo("Found {} keypairs and {} transactions".format(
            len(w.keypairs), len(w.txes)))
        click.echo("Default version byte: {}".format(w.default_wifnetwork))
        if keys:
            if not output:
                d = w.dump_keys(
                    version=versionprefix,
                    privkey_prefix_override=secretprefix)
                click.echo(json.dumps(d, sort_keys=True, indent=4))
            else:
                w.dump_keys(
                    output,
                    version=versionprefix,
                    privkey_prefix_override=secretprefix)
        else:
            if not output:
                d = w.dump_all(
                    version=versionprefix,
                    privkey_prefix_override=secretprefix)
                click.echo(json.dumps(d, sort_keys=True, indent=4))
            else:
                w.dump_all(
                    output,
                    version=versionprefix,
                    privkey_prefix_override=secretprefix)
        click.echo("Done")
    else:
        try:
            w = ProtobufWallet.load(filename)
            click.echo("Loaded file")
            if password:
                w.parse(passphrase=str(password))
            else:
                w.parse()
            click.echo("Found {} keypairs and {} transactions".format(
                len(w.keypairs), len(w.txes)))
            click.echo("Default version byte: {}".format(w.default_wifnetwork))
            if keys:
                if not output:
                    d = w.dump_keys()
                    click.echo(json.dumps(d, sort_keys=True, indent=4))
                else:
                    w.dump_keys(output)
            else:
                if not output:
                    d = w.dump_all()
                    click.echo(json.dumps(d, sort_keys=True, indent=4))
                else:
                    w.dump_all(output)
            click.echo("Done")
        except BaseException:
            click.echo("Error, cannot read wallet file")
