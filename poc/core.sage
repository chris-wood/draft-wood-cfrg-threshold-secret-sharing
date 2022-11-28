#!/usr/bin/sage
# vim: syntax=python

import sys

try:
    from sagelib.common import as_bytes
    from sagelib.polynomial import derive_poylnomial, polynomial_evaluate
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

mode_basic = 0x00

class DeterministicCommitment(object):
    def __init__(self, G, commitments):
        self.G = G
        self.commitments = commitments

    def serialize(self):
        commitment_enc = as_bytes("")
        for comm_i in self.commitments:
            commitment_enc = commitment_enc + self.G.serialize_element(comm_i)
        return commitment_enc

    def verify_for_share(self, id, value):
        def derive_public_point(G, i, commitments):
            public_point = G.identity()
            j = 0
            for comm_j in commitments:
                public_point += G.scalar_mult(comm_j, i ^ j)
                j += 1
            return public_point
        Y = self.G.scalar_base_mult(value)
        expected_Y = derive_public_point(self.G, id, self.commitments)
        return Y == expected_Y

def deserialize_deterministic_commitment(G, commitment):
    Nelement = G.element_byte_length()
    if len(commitment) % Nelement != 0:
        raise Exception("invalid commitment length")
    num_coefficients = len(commitment) / Nelement
    commitments = []
    for i in range(0, num_coefficients):
        c_i = G.deserialize_element(commitment[i*Nelement:(i+1)*Nelement])
        commitments.append(c_i)
    return DeterministicCommitment(G, commitments)

class SplitterContext(object):
    def __init__(self, mode, threshold, shared_secret, poly):
        self.mode = mode
        self.threshold = threshold
        self.shared_secret = shared_secret
        self.poly = poly

    def split(self, F, id):
        y = polynomial_evaluate(F, id, self.poly)
        return y

    def random_commitment(self, G):
        raise Exception("not implemented yet")

    def deterministic_commitment(self, G):
        commitments = []
        for coeff in self.poly:
            comm_i = G.scalar_base_mult(coeff)
            commitments.append(comm_i)
        return DeterministicCommitment(G, commitments)

def setup_splitter(F, mode, threshold, secret, rand):
    shared_secret, poly = derive_poylnomial(F, secret, rand, threshold, mode)
    return SplitterContext(mode, threshold, shared_secret, poly)