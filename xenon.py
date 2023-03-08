"""
Perform AES encryption and on the fly decryption using the Crypto libraries


"""

import argparse
import logging
import os
import sys
import base64

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Error! Requires the Python cryptography package to be installed. Exiting.")
    sys.exit(1)

class Xenon:
    """
    Takes a passphrase sets up an AES cipher.
    """
    BlockSize = 16  # Size of the blocks in bytes
    PlainTextLengthSize = 8  # Size of the payload length in the file header (a long int)
    Endianness = 'little'  # Byte ordering on CPU
    Magic = b"Xenon\00"

    class SHA:
        """
        Minimal class to store hashes of stuff
        """
        def __init__(self, data):
            self.len = len(data)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            self.sha = digest.finalize()

        def __repr__(self):
            return f"{self.sha.hex()}"

        def __len__(self):
            return self.len

    def __init__(self, passphrase):
        """
        Setup a cipher using the passphrase
        """

        # Check that the passphrase is a string. Trim any whitespace from it.

        if not isinstance(passphrase, str):
            raise TypeError("Passphrase must be a string")
        self.passphrase = bytearray(passphrase.strip(), "utf-8")

        # Derive the key from the passphrase.
        self.pp_sha = Xenon.SHA(self.passphrase)
        self.key = self.pp_sha.sha

        # Setup the initialisation vector/nonce
        self.iv = os.urandom(Xenon.BlockSize)
        logging.debug(f"Initialisation vector is {self.iv.hex()}")

        self.cipher = Cipher(algorithms.AES(key=self.key), modes.CBC(self.iv))

        # Setup place holders to record the length and SHA of the passphrase, plain text and cipher text
        self.pt_sha = None
        self.ct_sha = None

    def __repr__(self):
        exposed = 2 # Number of characters to expose in passphrase
        passphrase = self.passphrase.decode("utf-8")
        if len(passphrase) >= 2*exposed:
            passphrase = passphrase[0:exposed] + (len(passphrase) - 2 * exposed) * '*' + passphrase[-exposed:]
        s = [f"Passphrase {passphrase} ({self.pp_sha})"]
        if self.pt_sha:
            s.append(f"Plaintext is {len(self.pt_sha)} bytes ({self.pp_sha})")
        if self.ct_sha:
            s.append(f"Ciphertext is {len(self.ct_sha)} bytes ({self.cp_sha})")
        return ". ".join(s)

    def Encrypt(self, plaintext):
        """
        Encrypts the plaintext with the key.
        :param plaintext: bytearray
        :return ciphertext: bytearray

        We are using a block cipher, so the payload to be encrypted must be an exact multiple of the
        blocksize. So we therefore need to pad the plaintext with [0..blocksize-1] NULs at the end. But
        if we want to reconstruct the plaintext exactly we need to know how much padding has been added.

        Additionally, if we decrypt the file with the wrong key, various gibberish will be returned (which
        is what we would expect) but it won't actually throw an exception. So to detect whether we
        have correctly decrypted the file we have a "magic string" - a series of fixed bytes - which
        will allow us to tell if the decryption has been successful.

        So the payload is of the form (in bytes)
        Start   End   Value
        00      15    Initialisation vector/nonce
        16      23    Length of payload in bytes as a 64-bit little-endian integer
        24      29    Magic string ("Xenon" terminated by a NUL i.e. 0x58656e6f6e00)
        29  29+n-1    Plaintext of length n bytes
        29+n     p    Padding where p % blocksize == 0
        """

        # Setup a random Initilisation Vector and create the cipher.

        self.pt_sha = Xenon.SHA(plaintext)
        padlen = (Xenon.BlockSize - (len(Xenon.Magic) + self.pt_sha.len + Xenon.PlainTextLengthSize) % Xenon.BlockSize)\
                 % Xenon.BlockSize
        logging.debug(f"Plaintext is {len(self.pt_sha)} bytes ({self.pt_sha}). Padding is {padlen} bytes")
        encryptor = self.cipher.encryptor()
        payload = bytes(Xenon.BlockSize) + int.to_bytes(self.pt_sha.len, Xenon.PlainTextLengthSize, Xenon.Endianness) \
                  + Xenon.Magic + plaintext + bytes(padlen)
        logging.debug(f"Payload is {len(payload)} bytes")
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        self.ct_sha = Xenon.SHA(ciphertext)
        logging.debug(f"Ciphertext is {len(self.ct_sha)} bytes")
        return ciphertext

    def Decrypt(self, ciphertext):
        """
        Decrypts the ciphertext with the key
        :param ciphertext: bytearray
        :return plaintext: bytearray
        """
        self.ct_sha = Xenon.SHA(ciphertext)
        logging.debug(f"Ciphertext is {len(self.ct_sha)} bytes ({self.ct_sha})")
        decryptor = self.cipher.decryptor()
        payload = decryptor.update(ciphertext) + decryptor.finalize()
        ptxlen = int.from_bytes(payload[Xenon.BlockSize:Xenon.BlockSize+Xenon.PlainTextLengthSize], Xenon.Endianness)
        magicoffset = Xenon.BlockSize+Xenon.PlainTextLengthSize
        if payload[magicoffset:magicoffset+len(Xenon.Magic)] != Xenon.Magic:
            raise KeyError("Invalid key or not a Xenon file")
        plaintext = payload[Xenon.BlockSize + Xenon.PlainTextLengthSize + len(Xenon.Magic):\
                            Xenon.BlockSize + Xenon.PlainTextLengthSize + ptxlen + len(Xenon.Magic)]
        self.pt_sha = Xenon.SHA(plaintext)
        logging.debug(f"Plaintext is {len(self.pt_sha)} bytes ({self.pt_sha})")
        return plaintext

    def FormatOutput(self, ciphertext, linelen=60):
        """
        Takes the ciphertext bytes, converts to b64 and then spilts into lines of upto `linelen`
        :param ciphertext:
        :param linelen:
        :return:
        """
        b64ciphertext = base64.b64encode(ciphertext).decode("utf-8")
        yield "-- Xenon start ".ljust(linelen, "-")
        offset = 0
        while offset <= len(b64ciphertext):
            yield b64ciphertext[offset:offset+linelen]
            offset += linelen
        yield "-- Xenon end   ".ljust(linelen, "-")


    def EncryptFile(self, infile, outfile=None, linelen=60):
        """
        Encrypts a file
        :param infile: file of plaintext
        :param outfile: filename to write ciphertext to
        :return: None
        """
        if not outfile:
            outfile = infile + '.xenon'

        with open(infile, "rb") as inf:
            plaintext = inf.read()
            logging.debug(f"Read {len(plaintext)} bytes from {infile}")

        ciphertext = self.Encrypt(plaintext)

        with open(outfile, "w") as outf:
            for line in self.FormatOutput(ciphertext, linelen):
                print(line, file=outf)
            logging.debug(f"Written ciphertext to {outfile}")

    def DecryptFile(self, infile, outfile=None):
        """

        :param infile: Input file (b64 encoded ciphertext)
        :param outfile: Output file to write decrypted text to. (Not written if omitted)
        :return: plaintext
        """

        with open(infile) as inf:
            lines = inf.read().splitlines()
            logging.debug(f"Read {len(lines)} of ciphertext from {infile}")
            buffer = "".join(lines[1:-1])
            ciphertext = base64.b64decode(buffer)

        plaintext = self.Decrypt(ciphertext)
        if outfile:
            with open(outfile, "wb") as outf:
                outf.write(plaintext)
                logging.debug(f"Written {len(plaintext)} bytes of plaintext to {outfile}")
        return plaintext

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
        logging.debug(f"Got passphrase {passphrase} from command line")
    elif (keyfile := kwargs.get('keyfile')):
        with open(keyfile) as kf:
            passphrase = kf.read().strip()
            logging.debug(f"Got passphrase {passphrase} from keyfile {keyfile}")
    elif "XENON_PASSPHRASE" in os.environ:
        passphrase = os.environ["XENON_PASSPHRASE"]
        logging.debug(f"Got passphrase {passphrase} from environment variable XENON_PASSPHRASE")
    elif "XENON_KEYFILE" in os.environ:
        with open(os.environ["XENON_KEYFILE"]) as kf:
            passphrase = kf.read().strip()
            logging.debug(f"Got passphrase {passphrase} from keyfile {os.environ['XENON_KEYFILE']} from environment variable XENON_KEYFILE")
    else:
        raise ValueError("No passphrase found")

    return passphrase

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

    try:
        passphrase = GetPassPhrase(passphrase=args.passphrase, keyfile=args.keyfile)
    except FileNotFoundError as e:
        logging.critical(e)
        print(f"Error! {e}")
    else:
        x1 = Xenon(passphrase)
        x1.EncryptFile(args.input, args.output)
        x2 = Xenon(passphrase)
        plaintext = x2.DecryptFile(args.output, args.input+'.new')
        x3 = Xenon(passphrase+'123')
        try:
            x3.DecryptFile(args.output, args.input + '.bad')
        except KeyError as e:
            logging.critical(e)
            print(f"Error! {e}")
