import unittest
from unittest import mock
import pathlib
import hashlib
import os
import tempfile

import xenon

class TestSHASums(unittest.TestCase):
    """
    Test that the SHA256 sums of the test files are correct
    """
    SHAFile = "sha256sums"
    PassPhrase = "sausages"

    def test_sha_file_exists(self):
        """
        Does the SHA256sum file exist?
        :return:
        """
        if not pathlib.Path(TestSHASums.SHAFile).resolve().is_file():
            raise AssertionError(f"File {TestSHASums.SHAFile} does not exist")
    def  test_sha_values(self):
        """
        Do the test files SHA to the expected values?

        Read the list of filenames and SHAs from the SHAFile. Then for each file in the list
        :return:
        """

        # Read the file names and SHA sums into a dictionary and check that the three expected files are listed.
        with open(TestSHASums.SHAFile) as shafile:
            lines = shafile.read().splitlines()
        filedata = {l.split()[1]: l.split()[0] for l in lines}
        p = set(filedata.keys())
        q = set(["Jabberwocky.txt", "Jabberwocky.xenon", ".keyfile"])
        self.assertEqual(q-p, set(), f"Files {', '.join(sorted(list(q)))}")
        # For each of the files compute its SHA256 (using the Python hashlib rather than the cryptography one)
        for name, digest in filedata.items():
            # Check that the file exists...
            if not pathlib.Path(name).resolve().is_file():
                raise AssertionError(f"File {name} does not exist")
            with open(name, "rb") as f:
                contents = f.read()
                m = hashlib.sha256()
                m.update(contents)
                self.assertEqual(m.hexdigest(), digest)

    def test_passphrase(self):
        """
        Passphrase on its own
        :return:
        """
        phrase = "marmalade"
        passphrase = xenon.GetPassPhrase(passphrase=phrase)
        self.assertEqual(phrase, passphrase)

    def test_passphrase_with_keyfile(self):
        """
        Passphrase and keyfile both specified. Should return passphrase
        :return:
        """
        phrase = "marmalade"
        passphrase = xenon.GetPassPhrase(passphrase=phrase, keyfile=".keyfile")
        self.assertEqual(phrase, passphrase)

    def test_valid_keyfile(self):
        """
        Keyfile on its own
        """
        passphrase = xenon.GetPassPhrase(keyfile=".keyfile")
        self.assertEqual(passphrase, "sausages")

    @mock.patch.dict(os.environ, {"XENON_PASSPHRASE": "sausages"})
    def test_passphrase_env_var(self):
        passphrase = xenon.GetPassPhrase()
        self.assertEqual(passphrase, "sausages")

    @mock.patch.dict(os.environ, {"XENON_KEYFILE": ".keyfile"})
    def test_keyfile_env_var(self):
        passphrase = xenon.GetPassPhrase()
        self.assertEqual(passphrase, "sausages")

    def test_blank(self):
        """
        Nothing
        :return:
        """
        with self.assertRaises(ValueError):
            xenon.GetPassPhrase()

    def test_decryption_valid_key(self):
        """
        Decrypt the test file with the given key
        :return:
        """
        passphrase = xenon.GetPassPhrase(keyfile=".keyfile")
        x = xenon.Xenon(passphrase)
        plaintext = x.DecryptFile("Jabberwocky.xenon")
        with open("Jabberwocky.txt", "rb") as f:
            other = f.read()
        ptsha = hashlib.sha256()
        ptsha.update(plaintext)
        othersha = hashlib.sha256()
        othersha.update(other)
        self.assertEqual(ptsha.hexdigest(), othersha.hexdigest())

    def test_decryption_valid_key_write_to_file(self):
        """
        Decrypt the test file with the given key and write to a file
        :return:
        """
        tf = tempfile.NamedTemporaryFile()
        passphrase = xenon.GetPassPhrase(keyfile=".keyfile")
        x = xenon.Xenon(passphrase)
        x.DecryptFile("Jabberwocky.xenon", tf.name)
        with open(tf.name, "rb") as f:
            plaintext = f.read()
        with open("Jabberwocky.txt", "rb") as f:
            other = f.read()
        ptsha = hashlib.sha256()
        ptsha.update(plaintext)
        othersha = hashlib.sha256()
        othersha.update(other)
        self.assertEqual(ptsha.hexdigest(), othersha.hexdigest())

    def test_decryption_invalid_key(self):
        passphrase = xenon.GetPassPhrase(keyfile=".keyfile")+"123"
        x = xenon.Xenon(passphrase)
        with self.assertRaises(KeyError):
            x.DecryptFile("Jabberwocky.xenon")

    def test_encryption(self):
        passphrase = "marmalade"
        tf = tempfile.NamedTemporaryFile()
        x1 = xenon.Xenon(passphrase)
        x1.EncryptFile("Jabberwocky.txt", tf.name)
        x2 = xenon.Xenon(passphrase)
        plaintext = x2.DecryptFile(tf.name)
        with open("Jabberwocky.txt", "rb") as f:
            other = f.read()
        ptsha = hashlib.sha256()
        ptsha.update(plaintext)
        othersha = hashlib.sha256()
        othersha.update(other)
        self.assertEqual(ptsha.hexdigest(), othersha.hexdigest())

if __name__ == '__main__':
    unittest.main()



