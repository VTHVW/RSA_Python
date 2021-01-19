from Crypto.Util.number import getPrime, inverse
from Crypto.Random import get_random_bytes
from enum import Enum
import random
from euclidean_algorithm import *
from KeyIO import KeyFormat,KeyReader,KeyWriter

class KeyAlgorithm(Enum):
    """This Enum containg the types of funcion used in the algorithm to generate the rsa keys.
    """
    PHI="Euler totient function φ(n)"
    LAMBDA="Carmichael function λ(n)"

class RSA():
    """This class handles the creation of keys.
    It also translate the keys in the dictionary used by all the others modules. 

    Raises:
        RSA.InvalidAlgorithm: invalid function used in the algorithm.
    """
    InvalidAlgorithm = Exception("Invalid Algorith for RSA")
    DefaultMetadata = {"name":"Unknown","algorithm":"Unknown","length":"Unknown"}

    @staticmethod
    def gen_keys(bits=1024, name=None, algorithm=KeyAlgorithm.LAMBDA):
        """This method generates a RSA keys couple.
        See https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
        for more information.

        Args:
            bits (int, optional): the number of bits of the resulting key. Defaults to 1024.
            name (str, optional): the name that's saved in the metadata. Defaults to None.
            algorithm (KeyAlgorithm, optional): the function to be used. Defaults to KeyAlgorithm.LAMBDA.

        Raises:
            RSA.InvalidAlgorithm: invalid function used in the algorithm.

        Returns:
            encryption_exponent (int): the exponent to be used to encrypt.
            decryption_exponent (int): the exponent to be used to decrypt.
            module_n            (int): the module n to be used in encryption/decryption.
            metadata            (dict): a dictionary containg the key metadata.
        """
        metadata = {"name":name,"algorithm":{algorithm.name:algorithm.value},"length":bits}

        if(not name):
            name = RSA.__get_random_string()

        p_len_in_bits, q_len_in_bits = RSA.__divide_bits(bits,name)

        prime1_p = getPrime(
           p_len_in_bits,
           get_random_bytes 
        )
        prime2_q = getPrime(
           q_len_in_bits,
           get_random_bytes 
        )

        module_n = prime1_p*prime2_q

        if (algorithm == KeyAlgorithm.LAMBDA):
            # λ(n) = lcm(p-1,q-1), lcm(a,b) = |ab|/GCD(a,b)
            f_di_n = (prime1_p-1)*(prime2_q-1)//euclidean(prime1_p-1,prime2_q-1)
        elif (algorithm == KeyAlgorithm.PHI):
            f_di_n = (prime1_p-1)*(prime2_q-1)
        else:
            raise RSA.InvalidAlgorithm
        
        gcd = None
        while gcd != 1:
            # e and λ(n) or φ(n) must be cooprimes
            encryption_exponent = random.randint(3,f_di_n)
            # the extended auclidean algorith also calculate th inverse of e mod λ(n) or φ(n)
            gcd, decryption_exponent, _ = extended_euclidean(encryption_exponent, f_di_n)
        
        while decryption_exponent < 0:
            decryption_exponent += f_di_n

        # this function can also be used to calculate the inverse
        # decryption_exponent = inverse(encryption_exponent,f_di_n)

        return encryption_exponent, decryption_exponent, module_n, metadata

    @staticmethod
    def writeAndMakeKeys(e,d,n,metadata=None, format=KeyFormat.ASCII,priv_file_name="priv.key",pub_file_name="pub.key"):
        """Produce 2 dictionaries representing the keys, and writes them to a file.

        Args:
            e (Long Integer): the encryption exponent.
            d (Long Integer): the decryption exponent.
            n (Long Integer): the n module.
            metadata (dict, optional): a dictionary containing the keys metadata. Defaults to None.
            format (KeyFormat, optional): the format the files will be. Defaults to KeyFormat.ASCII.
            priv_file_name (str, optional): the name of the private key file. Defaults to "priv.key".
            pub_file_name (str, optional): the name of the public key file. Defaults to "pub.key".

        Returns:
            (dict,dict): 2 dictionaries, the first representig the private key, and the second the public one.
        """
        keys = RSA.makeKeys(e,d,n,metadata)
        return RSA.writeKeys(keys,format,priv_file_name,pub_file_name)

    @staticmethod
    def writeAndMakeKey(k,n,metadata=None, format=KeyFormat.ASCII,file_name="key.key",key_type="Unknown"):
        """Produce a dictionary representing the key and write it to a file.

        Args:
            k (Long Integer): the key exponent. 
            n (Long Integer): the key n module. 
            metadata (dict, optional): a dictionary containing the the key metadata. Defaults to None.
            format (KeyFormat, optional): the format the file will be. Defaults to KeyFormat.ASCII.
            file_name (str, optional): the name of the file the key will be saved onto. Defaults to "key.key".
            key_type (str, optional): either "private key" or "public key" everything else will be treated as "Unknown". Defaults to "Unknown".

        Returns:
            dict: a dictionary representing the key 
        """
        key = RSA.makeKey(k,n,metadata,key_type)
        return RSA.writeKey(key,format,file_name)

    @staticmethod
    def writeKeys(keys,format=KeyFormat.ASCII,priv_file_name="priv.key",pub_file_name="pub.key"):
        """Write a dictionary-type key pair to a file.
        The first key must be the private one.

        Args:
            keys (dict,dict): 2 dictionaries, the first representig the private key, and the second the public one.
            format (KeyFormat, optional): the format the keys will be saved as. Defaults to KeyFormat.ASCII.
            priv_file_name (str, optional): the private key file name. Defaults to "priv.key".
            pub_file_name (str, optional): the public key file name. Defaults to "pub.key".

        Returns:
            (dict,dict): 2 dictionaries, the first representig the private key, and the second the public one.
        """
        priv_key, pub_key = keys
        with open(priv_file_name,"w") as priv_file, open(pub_file_name,"w") as pub_file:
            if(format == KeyFormat.JSON):
                KeyWriter.write_json(priv_key,priv_file)
                KeyWriter.write_json(pub_key,pub_file)
            elif (format == KeyFormat.YML):
                KeyWriter.write_yml(priv_key,priv_file)
                KeyWriter.write_yml(pub_key,pub_file)
            elif (format == KeyFormat.RAW):
                KeyWriter.write_raw(priv_key,priv_file)
                KeyWriter.write_raw(pub_key,pub_file)
            elif (format == KeyFormat.ASCII):
                KeyWriter.write_ascii(priv_key,priv_file)
                KeyWriter.write_ascii(pub_key,pub_file)
            elif (format == KeyFormat.HEX):
                KeyWriter.write_hex(priv_key,priv_file)
                KeyWriter.write_hex(pub_key,pub_file)
        return keys

    @staticmethod
    def writeKey(key,format=KeyFormat.ASCII,file_name="key.key"):
        """Writes a dictionary-type key to a file.

        Args:
            key (dict): the key dictionary.
            format (KeyFormat, optional): the format the key will be saved as. Defaults to KeyFormat.ASCII.
            file_name (str, optional): the name of the key file. Defaults to "key.key".

        Returns:
            dict: the key dictionary.
        """
        with open(file_name,"w") as file:
            if(format == KeyFormat.JSON):
                KeyWriter.write_json(key,file)
            elif (format == KeyFormat.YML):
                KeyWriter.write_yml(key,file)
            elif (format == KeyFormat.RAW):
                KeyWriter.write_raw(key,file)
            elif (format == KeyFormat.ASCII):
                KeyWriter.write_ascii(key,file)
            elif (format == KeyFormat.HEX):
                KeyWriter.write_hex(key,file)
        return key

    @staticmethod
    def readKeys(priv_file_name,pub_file_name,format=KeyFormat.ASCII):
        """Read 2 Keys from a file and make them into a usables dictionaries pair.

        Args:
            priv_file_name (str): the file where the private key is saved.
            pub_file_name (str): the file where the public key is saved.
            format (KeyFormat, optional): the format of the files containg the keys. Defaults to KeyFormat.ASCII.

        Returns:
            (dict,dict): 2 dictionaries, the first representig the private key, and the second the public one.
        """
        with open(priv_file_name,"r") as priv_file, open(pub_file_name,"r") as pub_file:
            if(format == KeyFormat.JSON):
                priv_key = KeyReader.read_json(priv_file)
                pub_key = KeyReader.read_json(pub_file)
            elif (format == KeyFormat.YML):
                priv_key = KeyReader.read_yml(priv_file)
                pub_key = KeyReader.read_yml(pub_file)
            elif (format == KeyFormat.RAW):
                priv_key = KeyReader.read_raw(priv_file)
                pub_key = KeyReader.read_raw(pub_file)
            elif (format == KeyFormat.ASCII):
                priv_key = KeyReader.read_ascii(priv_file)
                pub_key = KeyReader.read_ascii(pub_file)
            elif (format == KeyFormat.HEX):
                priv_key = KeyReader.read_hex(priv_file)
                pub_key = KeyReader.read_hex(pub_file)
            
        return priv_key, pub_key

    @staticmethod
    def readKey(file_name, format=KeyFormat.ASCII):
        """Read a key from a file, and makes it into a usable dictionary.

        Args:
            file_name (str): the file where the key is saved.
            format (KeyFormat, optional): the format the key is saved as. Defaults to KeyFormat.ASCII.

        Returns:
            dict: a dictionary representing the key.
        """
        with open(file_name,"r") as file:
            if(format == KeyFormat.JSON):
                key = KeyReader.read_json(file)
            elif (format == KeyFormat.YML):
                key = KeyReader.read_yml(file)
            elif (format == KeyFormat.RAW):
                key = KeyReader.read_raw(file)
            elif (format == KeyFormat.ASCII):
                key = KeyReader.read_ascii(file)
            elif (format == KeyFormat.HEX):
                key = KeyReader.read_hex(file)
        return key

    @staticmethod
    def makeKeys(e,d,n,metadata=None):
        """Make a key pair dictionary from the exponents and the metadatas.

        Args:
            e (Long Integer): the encryption exponent.
            d (Long Integer): the decryption exponent.
            n (Long Integer): the n module of the keys.
            metadata (dict, optional): a dictionary containing the keys metadata. Defaults to None.

        Returns:
            (dict,dict): 2 dictionaries, the first representig the private key, and the second the public one.
        """
        if(not metadata):
            metadata=RSA.DefaultMetadata
        
        pub_key = {
            "type":"public key",
            "key exponent":e,
            "mod n":n,
            "metadata":metadata
        }
        priv_key = {
            "type":"private key",
            "key exponent":d,
            "mod n":n,
            "metadata":metadata
        }

        return priv_key,pub_key
    
    @staticmethod
    def makeKey(k,n,metadata=None,type="Unknown"):
        """Make a key dictionary from the exponent, the module and the metadatas.

        Args:
            k (Long Integer): the key exponent.
            n (Long Integer): the key n module.
            metadata (dict, optional): a dictionary contanining the key metadata. Defaults to None.
            type (str, optional): the key type, see writeAndMakeKey for more. Defaults to "Unknown".

        Returns:
            dict: a dictionary representing the key.
        """
        if(not metadata):
            metadata=RSA.DefaultMetadata
        
        key = {
            "type":type,
            "key exponent":k,
            "mod n":n,
            "metadata":metadata
        }

        return key
        
    @staticmethod
    def __divide_bits(bits,random_string):
        """Divide a bit quantity into 2 values that added make the original quantity.
        This method exist since the p and q prime generating numbers must have some difference in bits length,
        and the n module length is roughly the sum of the 2.
        This method ensure the length of the n value is the desired one.
        If a name is provided it's length it's used.
        If not then a random string is generated with the __get_random_string() method.

        Args:
            bits (int): a value representing a key length.
            random_string (str): a string used to randomize the process.

        Returns:
            (int,int): a integer pair a,b such that a+b=bits. 
        """
        if(bits>64):
            p_len = bits/2 - len(random_string)
            q_len = bits - p_len
        elif (bits<=1):
            p_len = 1
            q_len = 1
        else:
            p_len = bits/2
            q_len = bits - p_len

        return int(p_len), int(q_len)

    @staticmethod
    def __get_random_string():
        """This method generate a random string with length between 1 and 4 bytes.

        Returns:
            str: a random string.
        """
        return random.randbytes(
            random.randint(1,4)
        ).decode('utf-8', 'replace')
