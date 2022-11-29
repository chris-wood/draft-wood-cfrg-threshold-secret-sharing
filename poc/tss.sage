#!/usr/bin/sage
# vim: syntax=python

import os
import sys
import json
import itertools

try:
    from sagelib.common import to_hex, random_bytes, as_bytes
    from sagelib.field import Field64, Field128, Field255, FieldCurve25519
    from sagelib.core import setup_splitter, combine
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

mode_basic = 0x00

class TSSClient(object):
    def __init__(self, F, threshold, secret, rand):
        self.F = F
        self.context = setup_splitter(F, mode_basic, threshold, secret, rand)
    
    def random_share(self):
        x = self.F.random_scalar()
        y = self.context.split(self.F, x)
        x_enc = self.F.serialize_scalar(x)
        y_enc = self.F.serialize_scalar(y)
        return x_enc + y_enc

    def share(self, n):
        shares = []
        for i in range(1, n+1):
            x_i = i
            y_i = self.context.split(self.F, x_i)
            x_enc = self.F.serialize_scalar(x_i)
            y_enc = self.F.serialize_scalar(y_i)
            shares.append(x_enc + y_enc)
        return shares

class TSSAggregator(object):
    def __init__(self, F, threshold):
        self.F = F
        self.threshold = threshold

    def recover(self, share_set):
        if len(share_set) < self.threshold:
            raise Exception("invalid parameters")
        points = []
        for share in share_set:
            x = self.F.deserialize_scalar(share[0:F.SCALAR_SIZE])
            y = self.F.deserialize_scalar(share[F.SCALAR_SIZE:])
            points.append((x, y))

        return combine(self.F, self.threshold, points)

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

    client = TSSClient(F, k, secret, randomness)
    aggregator = TSSAggregator(F, k)

    shares = []
    for i in range(num_shares):
        share = client.random_share()
        shares.append(share)
        
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