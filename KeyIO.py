from enum import Enum
import math

from Crypto.Util.number import bytes_to_long as btl, long_to_bytes as ltb

import json
import yaml
import base64

WrongFileMode = Exception("The file mode cannot be binary")

DefaultMetadata = {"name":"Unknown","algorithm":"Unknown","length":"Unknown"}

class KeyFormat(Enum):
    """
    An Enum that contains the file format the keys can be saved as.
    Only JSON and YML can store metadata
    ASCII format will save only the key length and the name
    RAW and HEX will save only the key
    """
    JSON="JSON"     # no explenation needed
    # XML="XML"       xml sucks, won't implement it
    YML="YML"       # no explenation needed
    RAW="RAW"       # saves 2 integers base 10 (exponent,module n)
    ASCII="ASCII"   # save the key in a ssh-rsa like format (base64)
    HEX="HEX"       # saves 2 integers base 10 (exponent,module n)

class KeyWriter():
    """
    This class handles the write methods in the different format.

    Raises:
        WrongFileMode: the file cannot be binary.
    """

    @staticmethod
    def write_json(dict,file):
        """Writes the key in the JSON format.

        Args:
            dict (dict): a dictionary that descrybe the key.
            file (_io.TextIOWrapper): a file that can be written.

        Raises:
            WrongFileMode: the file cannot be binary.
        """
        if 'b' in file.mode:
            raise WrongFileMode
        file.write(json.dumps(
            dict,                   #the key
            indent=2,               #use 2 spaces as tab
            ensure_ascii=False      #enable the use of utf-8 characters
        ))

    # @staticmethod
    # def write_xml(dict,file):
    #     pass

    @staticmethod
    def write_yml(dict,file):
        """Writes the key in the YAML format.

        Args:
            dict (dict): a dictionary that descrybe the key.
            file (_io.TextIOWrapper): a file that can be written.

        Raises:
            WrongFileMode: the file cannot be binary.
        """
        if 'b' in file.mode:
            raise WrongFileMode
        file.write(yaml.dump(
            dict,
            allow_unicode=True
        ))

    @staticmethod
    def write_raw(dict,file):
        """Writes the key exponent and module as 2 base 10 integers.

        Args:
            dict (dict): a dictionary that descrybe the key.
            file (_io.TextIOWrapper): a file that can be written.

        Raises:
            WrongFileMode: the file cannot be binary.
        """
        if 'b' in file.mode:
            raise WrongFileMode
        file.write(str(dict['key exponent'])+"\n")
        file.write(str(dict['mod n']))

    @staticmethod
    def write_ascii(dict,file):
        """Writes the key in an armored ascii format.
        see https://coolaj86.com/articles/the-ssh-public-key-format/
        to know more about the key format.

        Args:
            dict (dict): a dictionary that descrybe the key.
            file (_io.TextIOWrapper): a file that can be written.

        Raises:
            WrongFileMode: the file cannot be binary.
        """
        if 'b' in file.mode:
            raise WrongFileMode

        # the data transformed from an integer to a byte array
        k = ltb(dict['key exponent'])
        n = ltb(dict['mod n'])
        # 4 bytes that represent the data lenght
        len_k=ltb(len(k),4)
        len_n=ltb(len(n),4)     

        key = len_k + k +len_n + n

        if(dict['type'] != "private key"):
            # the public key it's on one line only, and the data is separated with a space
            file.write("rsa ")
            file.write( base64.encodebytes(key).decode().replace("\n","")) #the replace remove the \n from the key

            # if the name it's in the metadata it will be printed in the file
            if dict['metadata'] and dict['metadata'] != 'Unknown':
                if dict['metadata']['name'] and dict['metadata']['name'] != "Unknown":
                    file.write(" " + dict['metadata']['name'].replace(" ",""))
        else:
            #the private key is saved on multiple lines
            if dict['metadata'] and dict['metadata'] != 'Unknown':
                if dict['metadata']['name'] and dict['metadata']['name'] != "Unknown":
                    # if the name it's in the metadata it will be printed in the file
                    # but as part of the key
                    name = dict['metadata']['name'].encode('utf-8')
                    len_name = ltb(len(name),4)
                    key+= len_name + name

            file.write("-----BEGIN RSA PRIVATE KEY-----\n")
            file.write(base64.encodebytes(key).decode())
            file.write("-----END RSA PRIVATE KEY-----")

    @staticmethod
    def write_hex(dict,file):
        """Writes the key exponent and module as 2 base 16 integers.

        Args:
            dict (dict): a dictionary that descrybe the key.
            file (_io.TextIOWrapper): a file that can be written.

        Raises:
            WrongFileMode: the file cannot be binary.
        """
        if 'b' in file.mode:
            raise WrongFileMode
        file.write(str(hex(dict['key exponent']))+"\n")
        file.write(str(hex(dict['mod n'])))

class KeyReader():
    """
    This class handles the read methods in the different format.

    Raises:
        WrongFileMode: the file cannot be binary.
    """

    @staticmethod
    def read_json(file):
        """A readeble file containg a key in the JSON format.

        Args:
            file (_io.TextIOWrapper): a file that can be read.

        Raises:
            WrongFileMode: the file cannot be binary.

        Returns:
            dict: a dictionary that descrybe the key.
        """
        if 'b' in file.mode:
            raise WrongFileMode
        data = file.read()
        return json.loads(data)

    # @staticmethod
    # def read_xml(file):
    #     pass

    @staticmethod
    def read_yml(file):
        """A readeble file containg a key in the YML format.

        Args:
            file (_io.TextIOWrapper): a file that can be read.

        Raises:
            WrongFileMode: the file cannot be binary.

        Returns:
            dict: a dictionary that descrybe the key.
        """
        if 'b' in file.mode:
            raise WrongFileMode
        data = file.read()
        return yaml.load(data)

    @staticmethod
    def read_raw(file):
        """A readeble file containg 2 base 10 integers.

        Args:
            file (_io.TextIOWrapper): a file that can be read.

        Raises:
            WrongFileMode: the file cannot be binary.

        Returns:
            dict: a dictionary that descrybe the key.
        """
        if 'b' in file.mode:
            raise WrongFileMode
        k = int(file.readline())
        n = int(file.readline())
        metadata=DefaultMetadata
        key = {
            "type":"Unknown",
            "key exponent":k,
            "mod n":n,
            "metadata":metadata
        }
        return key

    @staticmethod
    def read_ascii(file):
        """A readable file containg the key in a base64 format,
        see write_ascii for more information on the format.

        Args:
            file (_io.TextIOWrapper): a file that can be read.

        Raises:
            WrongFileMode: the file cannot be binary.

        Returns:
            dict: a dictionary that descrybe the key.
        """
        if 'b' in file.mode:
            raise WrongFileMode

        metadata=DefaultMetadata
        first_line = file.readline()
        if first_line == "-----BEGIN RSA PRIVATE KEY-----\n":
            type = "private key"
            #[:-30] remove the -----END RSA PRIVATE KEY----- part
            keys = base64.decodebytes(file.read()[:-30].encode())
        else:
            type = "public key"
            if len(first_line) == 3: # the name is saved in the file
                metadata['name'] = first_line.split()[-1].encode("utf-8")
            keys = base64.decodebytes(first_line.split()[1].encode())

        len_k=btl(keys[:4])         # length of the exponent
        keys = keys[4:]             # remove collected data from the array

        k=btl(keys[:len_k])         # the exponent
        keys = keys[len_k:]         # remove collected data from the array

        len_n = btl(keys[:4])       # length of the module
        keys = keys[4:]             # remove collected data from the array

        n = btl(keys[:len_n])       # the n module
        keys = keys[len_n:]         # remove collected data from the array

        if keys != b'':
            #if the name is saved it saves it
            name_len = btl(keys[:4])
            keys = keys[4:]
            name = keys[:name_len].decode('utf-8')
            metadata['name'] = name

        metadata['length'] = int(math.log2(n))
        key = {
            "type":type,
            "key exponent":k,
            "mod n":n,
            "metadata":metadata
        }
        return key

    @staticmethod
    def read_hex(file):
        """A readeble file containg 2 base 16 integers.

        Args:
            file (_io.TextIOWrapper): a file that can be read.

        Raises:
            WrongFileMode: the file cannot be binary.

        Returns:
            dict: a dictionary that descrybe the key.
        """
        if 'b' in file.mode:
            raise WrongFileMode
        k = int(file.readline(),16)
        n = int(file.readline(),16)
        metadata=DefaultMetadata
        key = {
            "type":"Unknown",
            "key exponent":k,
            "mod n":n,
            "metadata":metadata
        }
        return key