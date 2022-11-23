#!/usr/bin/sage
# vim: syntax=python

from typing import List, TypeVar
import struct

# Primitive types
Bool = bool
Bytes = bytes
Unsigned = int
Vec = List


# Base class for errors.
class Error(BaseException):
    def __init__(self, msg):
        self.msg = msg


# Errors
ERR_ABORT = Error('algorithm aborted')
ERR_DECODE = Error('decode failure')
ERR_ENCODE = Error('encode failure')
ERR_INPUT = Error('invalid input parameter')
ERR_VERIFY = Error('verification of the user\'s input failed')

# defined in RFC 3447, section 4.1
def I2OSP(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in reversed(range(0, length)):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP(ret, True) == val
    return ret

# defined in RFC 3447, section 4.2
def OS2IP(octets, skip_assert=False):
    ret = 0
    for octet in struct.unpack("=" + "B" * len(octets), octets):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP(ret, len(octets))
    return ret
