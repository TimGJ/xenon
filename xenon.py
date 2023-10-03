"""
Perform AES encryption and on the fly decryption using the Crypto libraries


"""

import argparse
import logging
import os
import sys
import subprocess


def Obscure(p, n=2):
    """
    Takes plaintext p and returns a string of the same length with the first and last n characters intact
    and replaces the rest with asterisks.
    """
    
    return p[0:n] + (len(p) - 2*n) * '*' + p[-n:]

def GetPassPhrase(**kwargs):

    """
    Get the passphrase. This is a little involved as there are various ways in which it might be supplied.
    It could be either supplied as a phrase e.g. "sausages" or a file containing the passphrase e.g.
    /home/missy/.xenonpassphrase. This could be specified as en environment variable or a command line option.

    As this will likely be run non-interactively, then we don't bother prompting for a password. Instead we just
    raise an exception.

    The order of precedence is that an option supplied on the command line trumps an environment variable and
    a passphrase trumps a keyfile location.
    """

    if (passphrase := kwargs.get('passphrase')):
        logging.debug(f"Got passphrase {Obscure(passphrase)} from command line")
    elif (keyfile := kwargs.get('keyfile')):
        with open(keyfile) as kf:
            passphrase = kf.read().strip()
            logging.debug(f"Got passphrase {Obscure(passphrase)} from keyfile {keyfile}")
    elif "XENON_PASSPHRASE" in os.environ:
        passphrase = os.environ["XENON_PASSPHRASE"]
        logging.debug(f"Got passphrase {Obscure(passphrase)} from environment variable XENON_PASSPHRASE")
    elif "XENON_KEYFILE" in os.environ:
        with open(os.environ["XENON_KEYFILE"]) as kf:
            passphrase = kf.read().strip()
            logging.debug(f"Got passphrase {Obscure(passphrase)} from keyfile {os.environ['XENON_KEYFILE']} from environment variable XENON_KEYFILE")
    else:
        raise ValueError("No passphrase found")
    return passphrase

if __name__ == '__main__':

    # Parse the command line arguments
    ap = argparse.ArgumentParser(description="On the fly decryption of encrypted files")
    ap.add_argument("--debug", "-d", help="Debug mode", action="store_true")
    ap.add_argument("--create", "-c", help="Create file", action="store_true")
    me = ap.add_mutually_exclusive_group()
    me.add_argument("--passphrase", "-p", help="Decryption passphrase")
    me.add_argument("--keyfile", "-f", help="Path to passphrase file")
    ap.add_argument("input", help="Input file")
    args = ap.parse_args()

    # Setup the logger
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)-9s %(message)s")

    try:
        passphrase = GetPassPhrase(passphrase=args.passphrase, keyfile=args.keyfile)
    except FileNotFoundError as e:
        logging.critical(e)
        print(f"Error! {e}")
    else:
        print(f"Passphrase is {Obscure(passphrase)}")
