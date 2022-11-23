#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import itertools

try:
    from sagelib.common import to_hex, random_bytes, as_bytes
    from sagelib.groups import Ristretto255
    from sagelib.polynomial import derive_poylnomial, polynomial_evaluate, derive_lagrange_coefficient
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def split_at(G, s, r, t, x):
    if t < 2:
        raise Exception("invalid parameters")

    shared_secret, polynomial_coefficients = derive_poylnomial(G.F, s, r, t)
    y = polynomial_evaluate(G.F, x, polynomial_coefficients)

    commitment = commit(G, polynomial_coefficients)

    x_enc = G.F.serialize_scalar(x)
    y_enc = G.F.serialize_scalar(y)
    
    return x_enc + y_enc + commitment, shared_secret

def random_split(G, s, r, t):
    if t < 2:
        raise Exception("invalid parameters")

    x = G.F.random_scalar()
    return split_at(G, s, r, t, x)

def recover(G, t, share_set):
    def polynomial_interpolation(points):
        L = [x for (x, _) in points]
        constant = 0
        for (x, y) in points:
            delta = (y * derive_lagrange_coefficient(G.F, x, L)) % G.F.MODULUS
            constant = (constant + delta) % G.F.MODULUS
        return constant

    if len(share_set) < t:
        raise Exception("invalid parameters")
    points = []
    for share in share_set:
        x = G.F.deserialize_scalar(share[0:G.F.SCALAR_SIZE])
        y = G.F.deserialize_scalar(share[G.F.SCALAR_SIZE:2*G.F.SCALAR_SIZE])
        points.append((x, y))

    s = polynomial_interpolation(points[:t])
    return G.F.serialize_scalar(s)

def commit(G, coefficients):
    commitment_enc = as_bytes("")
    for coeff in coefficients:
        comm_i = G.scalar_base_mult(coeff)
        commitment_enc = commitment_enc + G.serialize_element(comm_i)
    return commitment_enc

def derive_public_point(G, i, commitments):
    public_point = G.identity()
    j = 0
    for comm_j in commitments:
        public_point += G.scalar_mult(comm_j, i ^ j)
        j += 1
    return public_point

def verify_share(G, share):
    x = G.F.deserialize_scalar(share[0:G.F.SCALAR_SIZE])
    y = G.F.deserialize_scalar(share[G.F.SCALAR_SIZE:2*G.F.SCALAR_SIZE])
    commitment = share[2*G.F.SCALAR_SIZE:]
    
    Nelement = G.element_byte_length()
    if len(commitment) % Nelement != 0:
        raise Exception("invalid commitment length")
    num_coefficients = len(commitment) / Nelement
    commitments = []
    for i in range(0, num_coefficients):
        c_i = G.deserialize_element(commitment[i*Nelement:(i+1)*Nelement])
        commitments.append(c_i)

    Y = G.scalar_base_mult(y)
    expected_Y = derive_public_point(G, x, commitments)

    return expected_Y == Y

# Configure the setting
num_shares = 3
k = 2
secret = as_bytes("secret")
randomness = random_bytes(32)

ciphersuites = [
    ("VTSS-Ristretto255", "VTSS-Ristretto255", Ristretto255()),
]
for (fname, name, G) in ciphersuites:
    assert(k > 1)
    assert(k <= num_shares)

    shares = []
    secrets = []
    for i in range(num_shares):
        share, shared_secret = random_split(G, secret, randomness, k)
        if len(secrets) > 0:
            assert(str(shared_secret) == str(secrets[0]))
        shares.append(share)
        secrets.append(shared_secret)

    for share in shares:
        assert(verify_share(G, share))
        
    for share_set in itertools.combinations(shares, k):
        shared_secret = recover(G, k, share_set)
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