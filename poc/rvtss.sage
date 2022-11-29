#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import itertools

try:
    from sagelib.common import to_hex, random_bytes, as_bytes
    from sagelib.groups import Ristretto255
    from sagelib.core import setup_splitter, combine, deserialize_random_commitment
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

mode_auth_random = 0x02

class RVTSSClient(object):
    def __init__(self, G, threshold, secret, rand):
        self.F = G.F
        self.G = G
        self.context = setup_splitter(G.F, mode_auth_random, threshold, secret, rand)
    
    def random_share(self):
        x = self.F.random_scalar()
        y = self.context.split(self.F, x)
        commitment = self.context.random_commitment(self.G, x)

        x_enc = self.F.serialize_scalar(x)
        y_enc = self.F.serialize_scalar(y)
        commitment_enc = commitment.serialize()
        return x_enc + y_enc + commitment_enc

    def share(self, n):
        shares = []
        for i in range(1, n+1):
            x_i = i
            y_i = self.context.split(self.F, x_i)
            x_enc = self.F.serialize_scalar(x_i)
            y_enc = self.F.serialize_scalar(y_i)
            commitment = self.context.random_commitment(self.G, x_i)
            commitment_enc = commitment.serialize()
            shares.append(x_enc + y_enc + commitment_enc)
        return shares

class RVTSSAggregator(object):
    def __init__(self, G, threshold):
        self.F = G.F
        self.G = G
        self.threshold = threshold

    def recover(self, share_set):
        if len(share_set) < self.threshold:
            raise Exception("invalid parameters")
        points = []
        for share in share_set:
            x = self.F.deserialize_scalar(share[0:self.F.SCALAR_SIZE])
            y = self.F.deserialize_scalar(share[self.F.SCALAR_SIZE:2*self.F.SCALAR_SIZE])
            points.append((x, y))

        return combine(self.F, self.threshold, points)

    def verify(self, share):
        x = self.F.deserialize_scalar(share[0:self.F.SCALAR_SIZE])
        y = self.F.deserialize_scalar(share[self.F.SCALAR_SIZE:2*self.F.SCALAR_SIZE])
        commitment_enc = share[2*self.F.SCALAR_SIZE:]
        commitment = deserialize_random_commitment(self.G, commitment_enc)
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
    ("RVTSS-Ristretto255", "RVTSS-Ristretto255", Ristretto255()),
]
for (fname, name, G) in ciphersuites:
    assert(k > 1)
    assert(k <= num_shares)

    client = RVTSSClient(G, k, secret, randomness)
    aggregator = RVTSSAggregator(G, k)
    shares = []
    for i in range(num_shares):
        share = client.random_share()
        shares.append(share)

    for share in shares:
        assert(aggregator.verify(share))

    for share_pair in itertools.combinations(shares, 2):
        assert(aggregator.commitment(share_pair[0]) != aggregator.commitment(share_pair[1]))
        
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
