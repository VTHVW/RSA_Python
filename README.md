# RSA Python module
- [RSA Python module](#rsa-python-module)
  - [Summary](#summary)
  - [Dependencies](#dependencies)
  - [Modules Structure](#modules-structure)
    - [RSA.py](#rsapy)
    - [RSACrypt.py](#rsacryptpy)
      - [Why not two classes?](#why-not-two-classes)
    - [KeyIO.py](#keyiopy)
      - [Key Metadata](#key-metadata)
      - [Key Formats](#key-formats)
        - [Why not Other formats?](#why-not-other-formats)
          - [What about XML?](#what-about-xml)
      - [Classes](#classes)
        - [KeyWrite](#keywrite)
        - [KeyRead](#keyread)
    - [euclidean_algorithm.py](#euclidean_algorithmpy)
  - [How are the keys generated?](#how-are-the-keys-generated)
    - [What function is used?](#what-function-is-used)
  - [Why should I use this module?](#why-should-i-use-this-module)
  - [Want to help?](#want-to-help)

## Summary
This is a module that can be used to generate RSA keys.
Write and read keys from files in different formats.
And encrypt/decrypt some files & messages.

This was made as an homework to better understand RSA.

## Dependencies
This modules uses other modules that can be installed using the pip/pip3 utility:
- pycryptodome
- pyyaml

Those can be installed using these commands:
```bash
pip install pycryptodome
pip install pyyaml
```

## Modules Structure
The modules contains mostly Enums and static classes. These are classes that only have static methods. You can still instantiate an object from these classes but it would be rather pointless.

### RSA.py
This is the main class that generates the keys, writes them to a file, and can read them using methods from the [KeyIO](#keyio) modules.
The right way to import this modules is like this: `from RSA import *`. And it's also the way to import all the others.

Example of usage could be:
```python
e,d,n,meta = RSA.gen_keys(4096,"myname",KeyAlgorithm.LAMBDA)
private, public = RSA.writeAndMakeKeys(e,d,n,meta,KeyFormat.YML,"private_key.key","public_key.key")
```
This will allow us to use the keys to encrypt/decrypt messages with the [RSACrypt](#rsacryptpy) module.

In case we need to get a key from a file we need to use the RSA read methods. Like this:
```python
private, public = RSA.readKeys("private_key.key","public_key.key",KeyFormat.JSON)
```

### RSACrypt.py
This class perform encryption and decryption.
All data is inputted and outputted as a _bytes_ type. Only one method (*__lowlevel_crypt*) actually use integers. all other methods only use bytes and call *__lowlevel_crypt* to actually perform operation on the data.

Encrypted or "to encrypt" data can be accessed from:
  - a file `RSACrypt.crypt_file()`
  - a string `RSACrypt.crypt_string()`
  - a byte type array `RSACrypt.crypt_bytes()`

The data needs to be divided to chunks smaller than the n module for the encryption/decryption to work. These methods perform the division of the data, and then calls the *__crypt* methods to actually encrypt/decrypt the data.

#### Why not two classes?
While having 2 classes (one for encryption and one for decryption) seem reasonable, it would actually be redundant.
The operation that's performed in order to either encrypt or decrypt a message is the same.

For encryption: $m^e\mod n$ where m is the message, e the encryption exponent and n the key module part.

For Decryption: $m^d\mod n$ where m is the message, d the decryption exponent and n the key module part.

As you can see the only thing that change is the exponent.
So when these methods are used the operation performed will be encryption if the public key is passed as argument and decryption if the private key is passed as an argument.

### KeyIO.py
This module handles the actuall writing and reading from a file.
These methods transform the keys data (a dictionary) into a usable [format](#key-formats) and vice versa.

#### Key Metadata
These modules store some data besideds the key.
  - the name of the key owner.
  - the key length (in bits).
  - the [function](#what-function-is-used) used to generate the key.

The Key type (private or public) is also stored. If it's Unknown than the "Unknown" string is used as placeholder.

Only some [key formats](#key-formats) will keep these informations.

#### Key Formats
These are the format I decided to include:
- JSON - easy to read, and widely used.
- YAML - not as common but really pretty imo.
- ASCII - this is the format used by openssh to store keys.
  - the [public](https://coolaj86.com/articles/the-ssh-public-key-format/) and [private](https://coolaj86.com/articles/the-openssh-private-key-format/) formats are different but use the same logic.
  - the text is not actually ascii but base64.
- RAW - the key exponent and n module, saved as base$_{10}$ integers.
- HEX - the key exponent and n module, saved as base$_{16}$ integers.

Only the JSON and YAML format maintain all the metadata. The ASCII format maintain only the key type, length, and owner name but looses the key algorith used.
The RAW and HEX format save no metadata.

##### Why not Other formats?
Because I couldn't think of others.
Please feel free to suggest some.

###### What about XML?
I won't use the XML format because I hate it and find it really ugly.

#### Classes
The classes inside this module handles the writing and reading of the keys.

##### KeyWrite
This class is the opposite of [KeyRead](#keyread).
It require a file to be opened in the write and not binary mode, and passed to each method.
The methods in this class will not open a file by themself, this is done in the [RSA](#rsapy) class.

##### KeyRead
This class is the opposite of [KeyWrite](#keywrite).
It require a file to be opened in the read and not binary mode, and passed to each method.
The methods in this class will not open a file by themself, this is done in the [RSA](#rsapy) class.

### euclidean_algorithm.py
This module has two function:
- euclidean
- extended_euclidean

Which respectively use the euclidean algorithm and the extended euclidean algorithm to calculate the GCD of two numbers.
The extended algorithm is also used to calculate the module f(n) inverse of e.

To know more about this topic:
- [Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)
- [Euclidean algorithm](https://en.wikipedia.org/wiki/Euclidean_algorithm)
- [Bézout's identity](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity)

## How are the keys generated?
The process used to generate a pair of keys is the one described [here](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation)
### What function is used?
As said in the [RSA Wikipedia page](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) there are 2 funcion that can be used to generate a key.
So which method is used here? Both. Both methods can be used, and selected as `RSA.KeyAlgorithm.LAMBDA` or `RSA.KeyAlgorithm.PHI`.
Even though the phi-function-using algorithm is provided, is shall not be used because is not as strong as the lambda one. It's there only for educational purposes.

## Why should I use this module?
You shouldn't.

This was made only to better understand how RSA work.
Feel free to copy part of the code if you need to use it, but please don't claim it has your own. It would make me sad ☹.

## Want to help?
If you find something wrong in the code, a bug or think that something is missing please feel free to suggest changes.