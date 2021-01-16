from Crypto.Util.number import getPrime, inverse
from Crypto.Random import get_random_bytes
from enum import Enum
import random
from euclidean_algorithm import *
from KeyIO import KeyFormat,KeyReader,KeyWriter

class KeyAlgorithm(Enum):
    PHI="Euler totient function φ(n)"
    LAMBDA="Carmichael function λ(n)"

class RSA():
    InvalidAlgorithm = Exception("Invalid Algorith for RSA")

    @staticmethod
    def gen_keys(bits=1024, name=None, algorithm=KeyAlgorithm.LAMBDA):

        metadata = {"name":name,"algorithm":{algorithm.name:algorithm.value},"lenght":bits}

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
            f_di_n = (prime1_p-1)*(prime2_q-1)//euclidean(prime1_p-1,prime2_q-1)
        elif (algorithm == KeyAlgorithm.PHI):
            f_di_n = (prime1_p-1)*(prime2_q-1)
        else:
            raise RSA.InvalidAlgorithm
        
        gcd = None
        while gcd != 1:
            encryption_exponent = random.randint(3,f_di_n)
            gcd, decryption_exponent, _ = extended_euclidean(encryption_exponent, f_di_n)
        
        while decryption_exponent < 0:
            decryption_exponent += f_di_n

        # decryption_exponent = inverse(encryption_exponent,f_di_n)

        return encryption_exponent, decryption_exponent, module_n, metadata

    @staticmethod
    def writeKeys(e,d,n,metadata=None, format=KeyFormat.RAW,priv_file_name="priv.key",pub_file_name="pub.key"):
        if(not metadata):
            metadata={"name":"Unknown","algorithm":"Unknown","lenght":"Unknown"}
        
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

    @staticmethod
    def writeKey(k,n,metadata=None, format=KeyFormat.RAW,file_name="key.key",key_type="Unknown"):
        if(not metadata):
            metadata={"name":"Unknown","algorithm":"Unknown","lenght":"Unknown"}
        
        key = {
            "type":key_type,
            "key exponent":k,
            "mod n":n,
            "metadata":metadata
        }
        with open(file_name,"w") as file:
            if(format == KeyFormat.JSON):
                KeyWriter.write_json(key,file)
            elif (format == KeyFormat.YML):
                KeyWriter.write_yml(key,file)
            elif (format == KeyFormat.RAW):
                KeyWriter.write_raw(key,file)

    @staticmethod
    def readKeys(priv_file_name,pub_file_name,format=KeyFormat.RAW):
        with open(priv_file_name,"r") as priv_file, open(pub_file_name,"r") as pub_file:
            if(format == KeyFormat.JSON):
                priv_key = KeyReader.read_json(priv_file)
                pub_key = KeyReader.read_json(pub_file)
                return priv_key, pub_key
            elif (format == KeyFormat.YML):
                priv_key = KeyReader.read_yml(priv_file)
                pub_key = KeyReader.read_yml(pub_file)
                return priv_key, pub_key
            elif (format == KeyFormat.RAW):
                priv_key = KeyReader.read_raw(priv_file)
                pub_key = KeyReader.read_raw(pub_file)
                return priv_key, pub_key



    @staticmethod
    def readKey(file_name, format=KeyFormat.RAW):
        with open(file_name,"r") as file:
            if(format == KeyFormat.JSON):
                return KeyReader.read_json(file)
            elif (format == KeyFormat.YML):
                return KeyReader.read_yml(file)
            elif (format == KeyFormat.RAW):
                return KeyReader.read_raw(file)


    @staticmethod
    def makeKeys(e,d,n,meta=None):
        if(not meta):
            metadata={"name":"Unknown","algorithm":"Unknown","lenght":"Unknown"}
        
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
    def makeKey(k,n,meta=None,type="Unknown"):
        if(not meta):
            metadata={"name":"Unknown","algorithm":"Unknown","lenght":"Unknown"}
        
        key = {
            "type":type,
            "key exponent":k,
            "mod n":n,
            "metadata":metadata
        }

        return key

        
    @staticmethod
    def __divide_bits(bits,random_string):
        if(bits>64):
            p_len = bits/2 - len(random_string)*8
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
            return random.randbytes(
                random.randint(1,4)
            ).decode('utf-8', 'replace')
