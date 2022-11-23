#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json

try:
    from sagelib.field import Field64, Field128, Field255
    from sagelib.common import I2OSP
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

_as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

def to_hex(byte_string):
    if isinstance(byte_string, str):
        return "".join("{:02x}".format(ord(c)) for c in byte_string)
    if isinstance(byte_string, bytes):
        return "" + "".join("{:02x}".format(c) for c in byte_string)
    assert isinstance(byte_string, bytearray)
    return ''.join(format(x, '02x') for x in byte_string)


def random_bytes(n):
    return os.urandom(n)

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

def poylnomial_coefficient(F, r, index):
    return F.hash_to_scalar(r + I2OSP(index, 1))

def poylnomial_coefficients(F, s, r, t):
    if t < 2:
        raise Exception("invalid parameters")

    # Construct the polynomial from the random seed and threshold count
    polynomial_coefficients = [poylnomial_coefficient(F, s, 0)]
    for i in range(t - 1):
        coefficient = poylnomial_coefficient(F, r, i+1)
        polynomial_coefficients.append(coefficient)
    
    return polynomial_coefficients

def recover(F, t, share_set):
    def polynomial_interpolation(points):
        L = [x for (x, _) in points]
        constant = 0
        for (x, y) in points:
            delta = (y * derive_lagrange_coefficient(F, x, L)) % F.MODULUS
            constant = (constant + delta) % F.MODULUS
        return constant

    if len(share_set) < t:
        raise Exception("invalid parameters")
    points = []
    for share in share_set:
        x = F.deserialize_scalar(share[0:F.SCALAR_SIZE])
        y = F.deserialize_scalar(share[F.SCALAR_SIZE:])
        points.append((x, y))

    s = polynomial_interpolation(points[:t])
    return F.serialize_scalar(s)

def split_at(F, s, r, t, x):
    if t < 2:
        raise Exception("invalid parameters")

    # Construct and evaluate the polynomial at point x
    polynomial_coefficients = poylnomial_coefficients(F, s, r, t)
    y = polynomial_evaluate(F, x, polynomial_coefficients)

    x_enc = F.serialize_scalar(x)
    y_enc = F.serialize_scalar(y)

    # TODO(caw): return this from poly_coefficients?
    shared_secret = F.serialize_scalar(poylnomial_coefficient(F, s, 0))
    
    return x_enc + y_enc, shared_secret

def random_split(F, s, r, t):
    if t < 2:
        raise Exception("invalid parameters")

    x = F.random_scalar()
    return split_at(F, s, r, t, x)

# def vss_commit(G, coefficients):
#     vss_commitment = []
#     for coeff in coefficients:
#         comm_i = coeff * F.generator()
#         vss_commitment.append(comm_i)
#     return vss_commitment

# def derive_public_point(G, i, t, vss_commitment):
#     public_point = F.identity()
#     j = 0
#     for comm_j in vss_commitment:
#         public_point += comm_j * i**j
#         j += 1
#     return public_point

# def vss_verify(G, share_i, vss_commitment):
#     (i, sk_i) = share_i
#     SK_i = F.generator() * sk_i
#     SK_i_prime = derive_public_point(G, i, len(vss_commitment), vss_commitment)
#     return SK_i_prime == SK_i

# Configure the setting
num_shares = 3
k = 2
secret = _as_bytes("secret")
randomness = random_bytes(32)

ciphersuites = [
    ("TSS-F64", "TSS-F64", Field64),
    ("TSS-F128", "TSS-F128", Field128),
    ("TSS-F255", "TSS-F255", Field255),
]
for (fname, name, F) in ciphersuites:
    assert(k > 1)
    assert(k <= num_shares)

    shares = []
    secrets = []
    for i in range(num_shares):
        share, shared_secret = random_split(F, secret, randomness, k)
        if len(secrets) > 0:
            assert(str(shared_secret) == str(secrets[0]))
        shares.append(share)
        secrets.append(shared_secret)
        
    shared_secret = recover(F, k, shares)
    assert(shared_secret == secrets[-1])

    vector = {
        "name": name,
        "k": str(k),
        "secret": to_hex(secret),
        "randomness": to_hex(randomness),
        "shares": [to_hex(share) for share in shares],
        "shared_secret": to_hex(shared_secret),
    }

    with open(fname + ".json", "w") as fh:
        fh.write(str(json.dumps(vector, indent=2)))