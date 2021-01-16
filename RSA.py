from Crypto.Util.number import getPrime, inverse
from Crypto.Random import get_random_bytes
from enum import Enum
import random
from euclidean_algorithm import *

class KeyFormat(Enum):
    JSON="JSON"
    XML="XML"
    YML="YML"
    RAW="RAW"
    ASCII="ASCII"
    HEX="HEX"

class KeyAlgorithm(Enum):
    PHI="Euler totient function φ(n)"
    LAMBDA="Carmichael function λ(n)"

class RSA():
    InvalidAlgorithm = Exception("Invalid Algorith for RSA")

    @staticmethod
    def gen_keys(bits=1024, name=None, algorithm=KeyAlgorithm.LAMBDA):

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
            # print((prime1_p-1)*(prime2_q))
            # print()
            # print(euclidean(prime1_p-1,prime2_q-1))
            # print(f_di_n)
            # print()
            # import math
            # f_di_n = math.lcm(prime1_p-1,prime2_q-1)
            # print(f_di_n)
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

        return encryption_exponent, decryption_exponent, module_n


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
