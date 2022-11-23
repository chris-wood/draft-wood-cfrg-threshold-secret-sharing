#!/usr/bin/sage
# vim: syntax=python

import sys
import random
import hashlib

from hash_to_field import expand_message_xmd, hash_to_field

try:
    from sagelib.ristretto_decaf import Ed25519Point
    from sagelib.field import Field255
    from sagelib.common import I2OSP
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

xrange = range
_as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
_strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )

class Group(object):
    def __init__(self, name):
        self.name = name

    def generator(self):
        raise Exception("not implemented")

    def identity(self):
        raise Exception("not implemented")

    def order(self):
        raise Exception("not implemented")

    def serialize(self, element):
        raise Exception("not implemented")

    def deserialize(self, encoded):
        raise Exception("not implemented")

    def serialize_scalar(self, scalar):
        raise Exception("not implemented")

    def deserialize_scalar(self, scalar):
        raise Exception("not implemented")

    def element_byte_length(self):
        raise Exception("not implemented")

    def scalar_byte_length(self):
        raise Exception("not implemented")

    def hash_to_scalar(self, x):
        raise Exception("not implemented")

    def random_scalar(self):
        return random.randint(0, self.order() - 1)

    def random_nonzero_scalar(self):
        return random.randint(1, self.order() - 1)

    def __str__(self):
        return self.name

class GroupRistretto255(Group):
    def __init__(self):
        Group.__init__(self, "ristretto255")
        self.k = 128
        self.L = 48
        self.F = Field255
        self.field_bytes_length = 32

    def generator(self):
        return Ed25519Point().base()

    def order(self):
        return Ed25519Point().order

    def identity(self):
        return Ed25519Point().identity()

    def serialize(self, element):
        if element == self.identity():
            raise Exception("Identity element not permitted")

        return element.encode()

    def deserialize(self, encoded):
        element = Ed25519Point().decode(encoded)

        if element == self.identity():
            raise Exception("Identity element not permitted")

        return element

    def serialize_scalar(self, scalar):
        return I2OSP(scalar % self.order(), self.scalar_byte_length())[::-1]

    def deserialize_scalar(self, scalar):
        return int.from_bytes(scalar, "little") % self.order()

    def element_byte_length(self):
        return self.field_bytes_length

    def scalar_byte_length(self):
        return self.field_bytes_length

    def hash_to_scalar(self, msg, dst=""):
        return hash_to_field(msg, 1, dst, self.order(), 1, self.L, expand_message_xmd, hashlib.sha512, self.k)[0][0]

