# xenon
AES encryption and on-the-fly decryption of files

## So what does it do?

Xenon is designed to allow sensitive data (e.g. credentials)
to be encrypted at rest and then decrypted on the fly by an
application which requires them. 

It uses AES-256 encryption with Cipher Block Chaining to
encrypt the data using a text-based passphrase from which
the key is computed. 

The ciphertext can optionally be written to a file as b64
encoded and spilt into fixed-width lines. 

Xenon is derived from the (proprietary) Krypton libraries developed 
at UKFast. 

## Usage

The Xenon package should be installed into the local site
directory.

In order to use Xenon you should first create a Xenon object
with the passpherase

```python
import xenon
x = xenon.Xenon("sausages")
``` 

A Xenon object has two methods, `Encrypt` and `Decrypt`
which respectively encrypt or decrypt a `bytearray`. If you
are calling these directly for use with text, it's necessary
to encode the text accordingly. 

There are a couple of helper functions, `EncryptFile` and
`DecryptFile`, wrapped around the `Encrypt` and `Decrypt` 
methods designed for dealing with reading and writing text 
files (the normal use-case for the libraries). 

## Test files

The repo contains three test files to ensure that everything works. 
* `Jabberwocky.txt`: a sample of text (Lewis Carrol's nonsense poem Jabberwocky)
* `Jabberwocky.xenon`: `Jabberwock.txt` encrypted with the passhprase in `.keyfile`
* `.keyfile`: the passphrase used to create `Jabberwocky.xenon`

