#!/usr/bin/sage
# vim: syntax=python

# Definitions of finite fields used in this spec.

from __future__ import annotations
from sage.all import GF
from sagelib.common import ERR_DECODE, I2OSP, OS2IP, Bytes, Error, Unsigned, Vec

import random
from hashlib import sha256, sha512
from hash_to_field import expand_message_xmd, hash_to_field

_as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

# The base class for finite fields.
class Field:

    # The prime modulus that defines arithmetic in the field.
    MODULUS: Unsigned

    # Number of bytes used to encode each field element.
    SCALAR_SIZE: Unsigned

    def __init__(self, val):
        assert int(val) < self.MODULUS
        self.val = self.gf(val)

    @classmethod
    def zeros(cls, length: Unsigned) -> Vec[Field]:
        vec = [cls(cls.gf.zero()) for _ in range(length)]
        return vec

    @classmethod
    def rand_vec(cls, length: Unsigned) -> Vec[Field]:
        vec = [cls(cls.gf.random_element()) for _ in range(length)]
        return vec

    @classmethod
    def encode_vec(Field, data: Vec[Field]) -> Bytes:
        encoded = Bytes()
        for x in data:
            encoded += I2OSP(x.as_unsigned(), Field.SCALAR_SIZE)
        return encoded

    @classmethod
    def decode_vec(Field, encoded: Bytes) -> Vec[Field]:
        L = Field.SCALAR_SIZE
        if len(encoded) % L != 0:
            raise ERR_DECODE

        vec = []
        for i in range(0, len(encoded), L):
            encoded_x = encoded[i:i+L]
            x = OS2IP(encoded_x)
            if x >= Field.MODULUS:
                raise ERR_DECODE # Integer is larger than modulus
            vec.append(Field(x))
        return vec

    def __add__(self, other: Field) -> Field:
        return self.__class__(self.val + other.val)

    def __neg__(self) -> Field:
        return self.__class__(-self.val)

    def __mul__(self, other: Field) -> Field:
        return self.__class__(self.val * other.val)

    def inv(self) -> Field:
        return self.__class__(self.val^-1)

    def __eq__(self, other: Field) -> Field:
        return self.val == other.val

    def __sub__(self, other: Field) -> Field:
        return self + (-other)

    def __div__(self, other: Field) -> Field:
        return self * other.inv()

    def __pow__(self, n: Unsigned) -> Field:
        return self.__class__(self.val ^ n)

    def __str__(self):
        return str(self.val)

    def __repr__(self):
        return str(self.val)

    def as_unsigned(self) -> Unsigned:
        return int(self.gf(self.val))

# The finite field GF(2^32 * 4294967295 + 1).
class Field64(Field):
    MODULUS = 2^32 * 4294967295 + 1
    GEN_ORDER = 2^32
    SCALAR_SIZE = 8

    # Operational parameters
    gf = GF(MODULUS)

    @classmethod
    def random_scalar(cls):
        return random.randint(0, cls.MODULUS - 1)

    @classmethod
    def serialize_scalar(cls, scalar):
        return I2OSP(scalar % cls.MODULUS, cls.SCALAR_SIZE)

    @classmethod
    def deserialize_scalar(cls, scalar):
        return int.from_bytes(scalar, "big") % cls.MODULUS

    @classmethod
    def hash_to_scalar(cls, msg, dst=""):
        L = 48
        H = sha256
        expand = expand_message_xmd
        k = 128
        return hash_to_field(msg, 1, dst, cls.MODULUS, 1, L, expand, H, k)[0][0]


# The finite field GF(2^66 * 4611686018427387897 + 1).
class Field128(Field):
    MODULUS = 2^66 * 4611686018427387897 + 1
    GEN_ORDER = 2^66
    SCALAR_SIZE = 16

    # Operational parameters
    gf = GF(MODULUS)

    @classmethod
    def random_scalar(cls):
        return random.randint(0, cls.MODULUS - 1)

    @classmethod
    def serialize_scalar(cls, scalar):
        return I2OSP(scalar % cls.MODULUS, cls.SCALAR_SIZE)

    @classmethod
    def deserialize_scalar(cls, scalar):
        return int.from_bytes(scalar, "big") % cls.MODULUS

    @classmethod
    def hash_to_scalar(cls, msg, dst=""):
        L = 48
        H = sha256
        expand = expand_message_xmd
        k = 128
        return hash_to_field(msg, 1, dst, cls.MODULUS, 1, L, expand, H, k)[0][0]

# The finite field GF(2^255 - 19).
class Field255(Field):
    MODULUS = 2^255 - 19
    SCALAR_SIZE = 32

    # Operational parameters
    gf = GF(MODULUS)

    @classmethod
    def random_scalar(cls):
        return random.randint(0, cls.MODULUS - 1)

    @classmethod
    def serialize_scalar(cls, scalar):
        return I2OSP(scalar % cls.MODULUS, cls.SCALAR_SIZE)[::-1]

    @classmethod
    def deserialize_scalar(cls, scalar):
        return int.from_bytes(scalar, "little") % cls.MODULUS

    @classmethod
    def hash_to_scalar(cls, msg, dst=""):
        hash_input = _as_bytes("F255" + dst) + msg
        return int.from_bytes(sha512(hash_input).digest(), "little") % cls.MODULUS

