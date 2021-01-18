from math import log2
from Crypto.Util.number import bytes_to_long, long_to_bytes

class RSACrypt():

    @staticmethod
    def crypt_bytes(key,bytearray):
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
        return long_to_bytes(pow(bytes_to_long(enc),key['key exponent'],key['mod n']))