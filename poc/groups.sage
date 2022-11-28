#!/usr/bin/sage
# vim: syntax=python

import sys
import random
import hashlib

from hash_to_field import expand_message_xmd, hash_to_field

try:
    from sagelib.ristretto_decaf import Ed25519Point
    from sagelib.field import FieldCurve25519
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

    def generator2(self):
        raise Exception("not implemented")

    def identity(self):
        raise Exception("not implemented")

    def order(self):
        raise Exception("not implemented")

    def scalar_mult(self, A, k):
        return k * A

    def scalar_base_mult(self, k):
        return k * self.generator()

    def serialize_element(self, element):
        raise Exception("not implemented")

    def deserialize_element(self, encoded):
        raise Exception("not implemented")

    def element_byte_length(self):
        raise Exception("not implemented")

    def __str__(self):
        return self.name

class Ristretto255(Group):
    def __init__(self):
        Group.__init__(self, "ristretto255")
        self.k = 128
        self.L = 48
        self.F = FieldCurve25519
        self.field_bytes_length = 32

    def generator(self):
        return Ed25519Point().base()

    def generator2(self):
        element_enc = "d2ac2cd93039618e1ffaebdb5df9044eb6ebc8aa9d47d61ab1d45338f3c18d53"
        return self.deserialize_element(bytes.fromhex(element_enc))

    def order(self):
        return Ed25519Point().order

    def identity(self):
        return Ed25519Point().identity()

    def serialize_element(self, element):
        if element == self.identity():
            raise Exception("Identity element not permitted")
        return element.encode()

    def deserialize_element(self, encoded):
        element = Ed25519Point().decode(encoded)
        if element == self.identity():
            raise Exception("Identity element not permitted")
        return element

    def element_byte_length(self):
        return self.field_bytes_length
