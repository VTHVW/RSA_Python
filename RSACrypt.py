from math import log2
from Crypto.Util.number import bytes_to_long, long_to_bytes

class RSACrypt():
    """
    This class handles the crypting and decrypting processes.
    All methods return a byte type,
    except for __lowlevel_crypt, which operates with long ints,
    __ methods are suppoused to not be used even though they are static methods.
    This class has only static methods.
    It's not supposed to be instantiated.
    You are supposed to import this module like this:
    > from RSACrypt import *
    or
    > from RSACrypt import RSACrypt [as YOUCHOOSE]
    The Crypt in the name stands for both Encrypt and Decrypt
    since you can Encrypt using the public key as the "key" param
    and you can Decrypt using the private key as the "key" param.
    """

    @staticmethod
    def crypt_bytes(key,bytearray):
        """Perform decryption on a byte array.
        It's unusual to have a decrypted message in the form of a byte array using this modules
        but if you have one you could encrypt it with this method.

        Args:
            key (dict): a dictionary that descrybe the key.
            bytearray (bytes): a message to encrypt/decrypt.

        Returns:
            bytes: the encrypted/decrypted message as a byte array.
        """
        chunk = abs(int(log2(key['mod n'])))
        if(key['metadata'] != "Unknown"):
            if(key['metadata']['length']):
                chunk = key['metadata']['length']
        chunk //= 8
        msg = bytearray[0:chunk]
        cmsg = b''
        while msg:
            cmsg += RSACrypt.__crypt(key,msg)
            bytearray = bytearray[chunk:]
            msg = bytearray[0:chunk]
        return cmsg

    @staticmethod
    def crypt_string(key,str):
        """
        Perform encryption on a string.
        It's unusual to have an encrypted message in the form of a string using this modules
        but if you have one you could decrypt it with this method.

        Args:
            key (dict): a dictionary that descrybe the key.
            str (str): a message to encrypt/decrypt.

        Returns:
            bytes: the encrypted/decrypted message as a byte array.
        """
        chunk = abs(int(log2(key['mod n'])))
        if(key['metadata'] != "Unknown"):
            if(key['metadata']['length']):
                chunk = key['metadata']['length']
        chunk //= 8
        str = str.encode()
        msg = str[0:chunk]
        cmsg = b''
        while msg:
            cmsg += RSACrypt.__crypt(key,msg)
            str = str[chunk:]
            msg = str[0:chunk]
        return cmsg

    @staticmethod
    def crypt_file(key,filename):
        """
        Perform the reading from a file and encrypt/decrypt it's content.

        Args:
            key (dict): a dictionary that descrybe the key.
            filename (str): the name of the file to open.

        Returns:
            bytes: the encrypted/decrypted message as a byte array.
        """
        with open(filename,"rb") as file:
            chunk = abs(int(log2(key['mod n'])))
            if(key['metadata'] != "Unknown"):
                if(key['metadata']['length']):
                    chunk = key['metadata']['length']

            chunk //= 8
            msg = file.read(chunk)
            cmsg = b''
            while msg:
                cmsg += RSACrypt.__crypt(key,msg)
                msg = file.read(chunk)
            return cmsg

    @staticmethod
    def __crypt(key,enc):
        """
        Perform the encryption using the exponent part of a key and the module.
        like this:
        mᴷ mod n, where n is the key module, m is the message and k is the exponent part of a key.
        But the message and the crypted message are handled as bytes.

        Args:
            key (dict): a dictionary that descrybe the key.
            enc (bytes): a byte array that represent the message to be encrypted/decrypted.

        Returns:
            bytes: the encrypted/decrypted message as a byte array.
        """
        return long_to_bytes(
            RSACrypt.__lowlevel_crypt(key,bytes_to_long(enc))
        )

    @staticmethod
    def __lowlevel_crypt(key,enc_int):
        """
        Perform the encryption using the exponent part of a key and the module.
        like this:
        mᴷ mod n, where n is the key module, m is the message and k is the exponent part of a key.

        Args:
            key (dict): a dictionary that descrybe the key.
            enc_int (Long Integer): an integer that represent the message to be encrypted/decrypted.

        Returns:
            Long Integer: the encrypted/decrypted message as a int.
        """
        return pow(
            enc_int,
            key['key exponent'],
            key['mod n']
        )