"""
Perform AES encryption and on the fly decryption using the Crypto libraries


"""

import argparse
import logging
import os
import sys
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
class Xenon:
    """
    Takes a passphrase sets up an AES cipher.
    """
    BlockSize = 16  # Size of the blocks in bytes
    PlainTextLengthSize = 8  # Size of the payload length in the file header (a long int)
    Endianness = 'little'  # Byte ordering on CPU
    def __init__(self, passphrase):
        """
        Setup a cipher using the passphrase
        """

        # Check that the passphrase is a string. Trim any whitespace from it.

        if not isinstance(passphrase, str):
            raise TypeError("Passphrase must be a string")
        self.passphrase = passphrase.strip()

        # Derive the key from the passphrase.

        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytearray(self.passphrase, "utf8"))
        self.key = digest.finalize()
        logging.debug(f"Passphrase {self.passphrase} hashes to {self.key.hex()}")

        # Setup the initialisation vector/nonce
        self.iv = os.urandom(Xenon.BlockSize)
        logging.debug(f"Initialisation vector is {self.iv.hex()}")

        self.cipher = Cipher(algorithms.AES(key=self.key), modes.CBC(self.iv))

    def Encrypt(self, plaintext):
        """
        Encrypts the plaintext with the key.
        :param plaintext: bytearray
        :return ciphertext: bytearray

        We are using a block cipher, so the payload to be encrypted must be an exact multiple of the
        blocksize. So we therefore need to pad the plaintext with [0..blocksize-1] NULs at the end. But
        if we want to reconstruct the plaintext exactly we need to know how much padding has been added.

        So the payload is of the form (in bytes)
        Start   End   Value
        00      15    Initialisation vector/nonce
        16      23    Length of payload in bytes as a 64-bit little-endian integer
        24  24+n-1    Plaintext of length n bytes
        24+n     p    Padding where p % blocksize == 0
        """

        # Setup a random Initilisation Vector and create the cipher.

        ptxlen = len(plaintext)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(plaintext)
        padlen = (Xenon.BlockSize - (ptxlen + Xenon.PlainTextLengthSize) % Xenon.BlockSize) % Xenon.BlockSize
        logging.debug(f"Plain text is {ptxlen} bytes. Padding is {padlen} bytes")
        logging.debug(f"SHA-256 of plaintext is {digest.finalize().hex()}")
        encryptor = self.cipher.encryptor()
        payload = bytes(Xenon.BlockSize) + int.to_bytes(ptxlen, Xenon.PlainTextLengthSize, Xenon.Endianness) + plaintext + bytes(padlen)
        logging.debug(f"Payload is {len(payload)} bytes")
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        logging.debug(f"Ciphertext is {len(ciphertext)} bytes")
        return ciphertext

    def Decrypt(self, ciphertext):
        """
        Decrypts the ciphertext with the key
        :param ciphertext: bytearray
        :return plaintext: bytearray
        """

        logging.debug(f"Ciphertext is {len(ciphertext)} bytes")
        decryptor = self.cipher.decryptor()
        payload = decryptor.update(ciphertext) + decryptor.finalize()
        ptxlen = int.from_bytes(payload[Xenon.BlockSize:Xenon.BlockSize+Xenon.PlainTextLengthSize], Xenon.Endianness)
        plaintext = payload[Xenon.BlockSize + Xenon.PlainTextLengthSize:Xenon.BlockSize + Xenon.PlainTextLengthSize + ptxlen]
        digest = hashes.Hash(hashes.SHA256())
        digest.update(plaintext)
        logging.debug(f"Plain text is {ptxlen} bytes")
        logging.debug(f"SHA-256 of plaintext is {digest.finalize().hex()}")
        return plaintext

if __name__ == '__main__':

    # Parse the command line arguments
    ap = argparse.ArgumentParser(description="Encrypt and decrypt sensitive data")
    ap.add_argument("--debug", "-d", help="Debug mode", action="store_true")
    ap.add_argument("--input", "-i", help="Input file")
    ap.add_argument("--output", "-o", help="Output file")
    me = ap.add_mutually_exclusive_group()
    me.add_argument("--passphrase", "-p", help="Decryption passphrase")
    me.add_argument("--keyfile", "-f", help="Path to passphrase file")

    args = ap.parse_args()

    # Setup the logger
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)-9s %(message)s")


    # Get the passphrase. This is a little involved as there are various ways in which it might be supplied.
    # It could be either supplied as a phrase e.g. "sausages" or a file containing the passphrase e.g.
    # /home/missy/.xenonpassphrase. This could be specified as en environment variable or a command line option.
    #
    # As this will likely be run non-interactively, then we don't bother prompting for a password. Instead we just
    # raise an exception.
    #
    # The order of precedence is that an option supplied on the command line trumps an environment variable and
    # a passphrase trumps a keyfile location.

    if args.passphrase:
        passphrase = args.passphrase
        logging.debug(f"Got passphrase {passphrase} from command line")
    elif args.keyfile:
        try:
            passphrase = open(args.keyfile).read().strip()
        except (FileNotFoundError, PermissionError) as e:
            logging.critical(e)
        else:
            logging.debug(f"Read passphrase {passphrase} from keyfile {args.keyfile} from command line")
    elif "XENON_PASSPHRASE" in os.environ:
        passphrase = os.environ["XENON_PASSPHRASE"]
        logging.debug(f"Got passphrase {passphrase} from environment variable XENON_PASSPHRASE")
    elif "XENON_KEYFILE" in os.environ:
        try:
            passphrase = open(os.environ["XENON_KEYFILE"]).read().strip()
        except (FileNotFoundError, PermissionError) as e:
            logging.critical(e)
            sys.exit()
        else:
            logging.debug(f"Read passphrase {passphrase} from keyfile {os.environ['XENON_KEYFILE']} from environment variable XENON_KEYFILE")
    else:
        logging.critical("No passphrase specified. Exiting.")
        sys.exit()

    # Now get the payload to be encrypted or decrypted. If we haven't specified a --input option read it from stdin

    if args.input:
        try:
            payload = open(args.input).read()
        except (FileNotFoundError, PermissionError) as e:
            logging.critical(e)
            sys.exit()
        else:
            logging.debug(f"Read {len(payload)} bytes from file {args.input}")
    else:
        payload = sys.stdin.read()
        logging.debug(f"Read {len(payload)} bytes from sys.stdin")

    # Now having got the payload and passphrase create a Xenon object using it...

    x1 = Xenon(passphrase)
    ct = x1.Encrypt(bytearray(payload, "utf-8"))
    x2 = Xenon(passphrase)
    pt = x2.Decrypt(ct)
    print(pt.decode("utf-8"))