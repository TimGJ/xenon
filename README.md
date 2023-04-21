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

Xenon is inspired the (proprietary) Krypton libraries developed 
at UKFast. 

## Usage

The Xenon package should be installed into the local site
directory.

In order to use Xenon you should first create a Xenon object
with the passphrase

```python
import xenon
x = xenon.Xenon("sausages")
``` 

A Xenon object has two principal methods, `Encrypt` and `Decrypt`
which respectively encrypt or decrypt payload.

```python
ciphertext = x.Encrypt(b"Hello world")
```
and

```python
plaintext = x.Decrypt(ciphertext)
```

These accept and return `bytes`. So If you are calling these directly 
for use with text, it's necessary to encode the text accordingly. 

There are a couple of helper functions, `EncryptFile` and
`DecryptFile`, wrapped around the `Encrypt` and `Decrypt` 
methods designed for dealing with reading and writing text 
files (the normal use-case for the libraries). 

```python
x.EncryptFile(infile, outfile)
```

and

```python
text = x.DecryptFile(infile, outfile)
```

The `DecrpytFile` method also returns the plaintext to the caller is this
is the most common use-case (decrypting e.g. config files on the fly).

Note that this is returned as bytes and so will need the approriate decoding
applying if, for example, it is to be loaded as JSON or YAML.

## Test files

The repo contains three test files to ensure that everything works. 
* `Jabberwocky.txt`: a sample of text (Lewis Carroll's nonsense poem Jabberwocky)
* `Jabberwocky.xenon`: `Jabberwockiy.txt` encrypted with the passphrase in `.keyfile`
* `.keyfile`: the passphrase used to create `Jabberwocky.xenon`

# Disclaimer

* This software comes with absolutely no warranty whatsoever. 
* If your key leaks and you get hacked then it's not my fault.
* If you forget or lose your key then you won't be able to decrypt stuff. Thats the whole point.
* err. That's it
