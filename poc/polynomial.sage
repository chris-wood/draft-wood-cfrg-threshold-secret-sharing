#!/usr/bin/sage
# vim: syntax=python

import sys

try:
    from sagelib.common import I2OSP
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

_as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

def derive_lagrange_coefficient(F, i, L):
    assert(i != 0)
    for j in L:
      assert(j != 0)
    in_L = False
    for x in L:
        if i == x:
            in_L = True
    assert(in_L)

    num = 1
    den = 1
    for j in L:
        if j == i:
            continue
        num = (num * j) % F.MODULUS
        den = (den * (j - i)) % F.MODULUS
    L_i = (num * inverse_mod(den, F.MODULUS)) % F.MODULUS
    return L_i

def polynomial_evaluate(F, x, coeffs):
    value = 0
    for coeff in reversed(coeffs):
        value = (value * x) % F.MODULUS
        value = (value + coeff) % F.MODULUS
    return value

def derive_poylnomial_coefficient(F, r, t, index):
    ctx = F.serialize_scalar(t) + _as_bytes("-") + F.serialize_scalar(index)
    return F.hash_to_scalar(r, ctx)

def derive_poylnomial(F, s, r, t):
    if t < 2:
        raise Exception("invalid parameters")

    # Construct the polynomial from the random seed and threshold count
    base = derive_poylnomial_coefficient(F, s, t, 0)
    polynomial_coefficients = [base]
    for i in range(t - 1):
        coefficient = derive_poylnomial_coefficient(F, r, t, i+1)
        polynomial_coefficients.append(coefficient)
    
    return F.serialize_scalar(base), polynomial_coefficients

