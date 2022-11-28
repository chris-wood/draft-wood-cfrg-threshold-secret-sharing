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
    from sagelib.core import setup_splitter, deserialize_deterministic_commitment
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

mode_auth_deterministic = 0x01

class DVTSSClient(object):
    def __init__(self, G, threshold, secret, rand):
        self.F = G.F
        self.G = G
        self.context = setup_splitter(G.F, mode_auth_deterministic, threshold, secret, rand)
    
    def random_share(self):
        x = self.F.random_scalar()
        y = self.context.split(self.F, x)
        commitment = self.context.deterministic_commitment(self.G)

        x_enc = self.F.serialize_scalar(x)
        y_enc = self.F.serialize_scalar(y)
        commitment_enc = commitment.serialize()
        return x_enc + y_enc + commitment_enc

    def share(self, n):
        shares = []
        commitment = self.context.deterministic_commitment(self.G)
        commitment_enc = commitment.serialize()
        for i in range(1, n+1):
            x_i = i
            y_i = self.context.split(self.F, x_i)
            x_enc = self.F.serialize_scalar(x_i)
            y_enc = self.F.serialize_scalar(y_i)
            shares.append(x_enc + y_enc + commitment_enc)
        return shares

class DVTSSAggregator(object):
    def __init__(self, G, threshold):
        self.F = G.F
        self.G = G
        self.threshold = threshold

    def recover(self, share_set):
        def polynomial_interpolation(points):
            L = [x for (x, _) in points]
            constant = 0
            for (x, y) in points:
                delta = (y * derive_lagrange_coefficient(self.F, x, L)) % self.F.MODULUS
                constant = (constant + delta) % self.F.MODULUS
            return constant

        if len(share_set) < self.threshold:
            raise Exception("invalid parameters")
        points = []
        for share in share_set:
            x = self.F.deserialize_scalar(share[0:self.F.SCALAR_SIZE])
            y = self.F.deserialize_scalar(share[self.F.SCALAR_SIZE:2*self.F.SCALAR_SIZE])
            points.append((x, y))

        s = polynomial_interpolation(points[:self.threshold])
        return self.F.serialize_scalar(s)

    def verify(self, share):
        x = self.F.deserialize_scalar(share[0:self.F.SCALAR_SIZE])
        y = self.F.deserialize_scalar(share[self.F.SCALAR_SIZE:2*self.F.SCALAR_SIZE])
        commitment_enc = share[2*self.F.SCALAR_SIZE:]
        commitment = deserialize_deterministic_commitment(self.G, commitment_enc)
        return commitment.verify_for_share(x, y)

    def commitment(self, share):
        commitment_enc = share[2*self.F.SCALAR_SIZE:]
        return commitment_enc


# Configure the setting
num_shares = 3
k = 2
secret = as_bytes("secret")
randomness = random_bytes(32)

ciphersuites = [
    ("DVTSS-Ristretto255", "DVTSS-Ristretto255", Ristretto255()),
]
for (fname, name, G) in ciphersuites:
    assert(k > 1)
    assert(k <= num_shares)

    client = DVTSSClient(G, k, secret, randomness)
    aggregator = DVTSSAggregator(G, k)
    shares = []
    for i in range(num_shares):
        share = client.random_share()
        shares.append(share)

    for share in shares:
        assert(aggregator.verify(share))

    expected_commitment = aggregator.commitment(shares[0])
    for i, share in enumerate(shares):
        if i == 0:
            continue
        assert(aggregator.commitment(share) == expected_commitment)
        
    for share_set in itertools.combinations(shares, k):
        shared_secret = aggregator.recover(share_set)
        assert(shared_secret == client.context.shared_secret)

    vector = {
        "name": name,
        "k": str(k),
        "secret": to_hex(secret),
        "randomness": to_hex(randomness),
        "shares": [to_hex(share) for share in shares],
        "shared_secret": to_hex(client.context.shared_secret),
    }

    with open(fname + ".json", "w") as fh:
        fh.write(str(json.dumps(vector, indent=2)))
