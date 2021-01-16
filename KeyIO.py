from enum import Enum

import json
import yaml

class KeyFormat(Enum):
    JSON="JSON"
    # XML="XML"
    YML="YML"
    RAW="RAW"
    ASCII="ASCII"
    HEX="HEX"

class KeyWriter():

    @staticmethod
    def write_json(dict,file):
        file.write(json.dumps(dict, indent=2))

    # @staticmethod
    # def write_xml(dict,file):
    #     pass

    @staticmethod
    def write_yml(dict,file):
        file.write(yaml.dump(dict))

    @staticmethod
    def write_raw(dict,file):
        file.write(str(dict['key exponent'])+"\n")
        file.write(str(dict['mod n']))

    @staticmethod
    def write_ascii(dict,file):
        pass

    @staticmethod
    def write_hex(dict,file):
        pass

class KeyReader():

    @staticmethod
    def read_json(file):
        data = file.read()
        return json.loads(data)

    # @staticmethod
    # def read_xml(file):
    #     pass

    @staticmethod
    def read_yml(file):
        data = file.read()
        return yaml.load(data)

    @staticmethod
    def read_raw(file):
        k = int(file.readline())
        n = int(file.readline())
        metadata={"name":"Unknown","algorithm":"Unknown","lenght":"Unknown"}
        key = {
            "type":"Unknown",
            "key exponent":k,
            "mod n":n,
            "metadata":metadata
        }
        return key

    @staticmethod
    def read_ascii(file):
        pass

    @staticmethod
    def read_hex(file):
        pass
