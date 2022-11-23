#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import itertools

try:
    from sagelib.common import to_hex, random_bytes, as_bytes
    from sagelib.field import Field64, Field128, Field255, FieldCurve25519
    from sagelib.polynomial import derive_poylnomial, polynomial_evaluate, derive_lagrange_coefficient
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def split_at(F, s, r, t, x):
    if t < 2:
        raise Exception("invalid parameters")

    shared_secret, polynomial_coefficients = derive_poylnomial(F, s, r, t)
    y = polynomial_evaluate(F, x, polynomial_coefficients)

    x_enc = F.serialize_scalar(x)
    y_enc = F.serialize_scalar(y)
    
    return x_enc + y_enc, shared_secret

def random_split(F, s, r, t):
    if t < 2:
        raise Exception("invalid parameters")

    x = F.random_scalar()
    return split_at(F, s, r, t, x)

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

num_shares = 3
k = 2
secret = as_bytes("secret")
randomness = random_bytes(32)

ciphersuites = [
    ("TSS-F64", "TSS-F64", Field64),
    ("TSS-F128", "TSS-F128", Field128),
    ("TSS-F255", "TSS-F255", Field255),
    ("TSS-FCurve25519", "TSS-FCurve25519", FieldCurve25519)
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
        
    for share_set in itertools.combinations(shares, k):
        shared_secret = recover(F, k, share_set)
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