---
title: "Threshold Secret Sharing"
abbrev: "Threshold Secret Sharing"
category: info

docname: draft-wood-cfrg-threshold-secret-sharing-latest
submissiontype: IRTF
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - threshold secret sharing
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "chris-wood/draft-wood-cfrg-threshold-secret-sharing"
  latest: "https://chris-wood.github.io/draft-wood-cfrg-threshold-secret-sharing/draft-wood-cfrg-threshold-secret-sharing.html"

author:
 -
    fullname: Christopher A. Wood
    organization: Cloudflare
    email: caw@heapingbits.net

normative:

informative:
  HASH-TO-CURVE: I-D.irtf-cfrg-hash-to-curve
  RISTRETTO: I-D.irtf-cfrg-ristretto255-decaf448


--- abstract

This document specifies two variants of threshold secret sharing schemes.
The first variant, called unverifiable, is based on Shamir's original scheme,
and the second variant, called verifiable, is based on Feldman's scheme.

--- middle

# Introduction

Threshold secret sharing is a well-known and widely used cryptographic
algorithm that has a number of applications, ranging from distributed
key generation, threshold digital signatures, and privacy-preserving
measurement. Threshold secret sharing allows the owner of a secret
to split it into independent shares, each of which reveals nothing about
the secret on its own. However, the threshold number of shares for a secret
can be efficiently recombined by an aggregator to recover a shared secret.

The original threshold secret sharing scheme is due to Shamir {{?ShamirSecretSharing=DOI.10.1145/359168.359176}}.
However, many variations exist with different properties. For example, some
secret sharing schemes can be verifiable {{?Feldman=DOI.10.1109/SFCS.1987.4}}, which allows an aggregator to check
that the share is valid. Other schemes allow metadata to be associated with
a secret share and authenticated during secret recovery {{?ADSS=DOI.10.2478/popets-2020-0082}}.

This document specifies a simple abstraction for threshold secret sharing
with two different modes: unverifiable and verifiable. We denote TSS and VTSS
as the unverifiable and verifiable modes, respectively.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following notation is used throughout the document.

* `random_bytes(n)`: Outputs `n` bytes, sampled uniformly at random
using a cryptographically secure pseudorandom number generator (CSPRNG).
* `len(l)`: Outputs the length of input list `l`, e.g., `len([1,2,3]) = 3)`.
* `range(a, b)`: Outputs a list of integers from `a` to `b-1` in ascending order, e.g., `range(1, 4) = [1,2,3]`.
* `pow(a, b)`: Outputs the integer result of `a` to the power of `b`, e.g., `pow(2, 3) = 8`.
* `str(x)`: Outputs an ASCII string encoding of the integer input `x`, e.g., `str(1) = "1"`.
* \|\| denotes concatenation of byte strings, i.e., `x || y` denotes the byte string `x`, immediately followed by
  the byte string `y`, with no extra separator, yielding `xy`.
* nil denotes an empty byte string.

Unless otherwise stated, we assume that secrets are sampled uniformly at random
using a cryptographically secure pseudorandom number generator (CSPRNG); see
{{?RFC4086}} for additional guidance on the generation of random numbers.

# Cryptographic Dependencies

Threshold secret sharing signing depends on the following cryptographic constructs:

- Finite Field, {{dep-field}};
- Prime-Order Group, {{dep-pog}};

These are described in the following sections.

## Finite Field {#dep-field}

A finite field `F` is a field of finite size, where the size is referred to as the order.
We refer to an element of the field as a Scalar. As a field, each Scalar supports normal
arithmetic operations, including multiplication, addition, subtraction, and division. Finite
fields are commonly implemented over the integers modulo a prime p, defined as the `MODULUS`.
Each field also has an associated parameter called `SCALAR_SIZE`, which is the number of
bytes used to encode a field element as a byte string.

For convenience, each field has an associated function called `RandomScalar` that
is used to sample a uniformly random Scalar from the field. Refer to {{random-scalar}}
for implementation guidance.

Each field `F` also has the following encoding and decoding functions:

- HashToScalar(x, ctx): Deterministically maps input `x` to a Scalar element using the domain
  separation tag `ctx`.
- SerializeScalar(s): Maps a Scalar `s` to a canonical byte array `buf` of fixed length `SCALAR_SIZE`.
- DeserializeScalar(buf): Attempts to map a byte array `buf` to a `Scalar` `s`.
  This function can raise an error if deserialization fails.

### Field F64

This named field uses MODULUS=2^32 * 4294967295 + 1 with SCALAR_SIZE=8. The implementation of
the field functions defined in {{dep-field}} is as follows.

- HashToScalar(x, ctx): Implemented as hash_to_field(m, 1) from {{HASH-TO-CURVE, Section 5.2}}
  using `expand_message_xmd` with SHA-256 with parameters DST = "F128" || ctx,
  F set to the scalar field, p set to `MODULUS`, m = 1, and L = TBD.
- SerializeScalar(s): Implemented by outputting the big-endian 8-byte encoding of
  the Scalar value.
- DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar from a
  big-endian 8-byte string. This function can fail if the input does not
  represent a Scalar in the range \[0, MODULUS - 1\].

### Field F128

This named field uses MODULUS=2^66 * 4611686018427387897 + 1 with SCALAR_SIZE=16. The implementation of
the field functions defined in {{dep-field}} is as follows.

- HashToScalar(x, ctx): Implemented as hash_to_field(m, 1) from {{HASH-TO-CURVE, Section 5.2}}
  using `expand_message_xmd` with SHA-256 with parameters DST = "F128" || ctx,
  F set to the scalar field, p set to `MODULUS`, m = 1, and L = TBD.
- SerializeScalar(s): Implemented by outputting the big-endian 16-byte encoding of
  the Scalar value.
- DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar from a
  big-endian 16-byte string. This function can fail if the input does not
  represent a Scalar in the range \[0, MODULUS - 1\].

### Field F255

This named field uses MODULUS=2^255 - 19 with SCALAR_SIZE=32. The implementation of
the field functions defined in {{dep-field}} is as follows.

- HashToScalar(x, ctx): Implemented by computing SHA-512("F255" \|\| DST \|\| x) and mapping the
  output to a Scalar as described in {{RISTRETTO, Section 4.4}}.
- SerializeScalar(s): Implemented by outputting the little-endian 32-byte encoding of
  the Scalar value with the top three bits set to zero.
- DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar from a
  little-endian 32-byte string. This function can fail if the input does not
  represent a Scalar in the range \[0, `G.Order()` - 1\]. Note that this means the
  top three bits of the input MUST be zero.

## Prime-Order Group {#dep-pog}

A prime-order group `G` is an an abelian group of prime order `p`, denoted `ORDER`. Integers, taken modulo
the group order `p`, form a finite field of order p.

The group operation for `G` is addition `+` with identity element `I`. For any elements
`A` and `B` of the group `G`, `A + B = B + A` is also a member of `G`. Also, for any
`A` in `G`, there exists an element `-A` such that `A + (-A) = (-A) + A = I`. For
convenience, we use `-` to denote subtraction, e.g., `A - B = A + (-B)`.
We denote equality comparison as `==` and assignment of values by `=`.
It is assumed that group element addition, negation, and equality comparisons can be
efficiently computed for arbitrary group elements.

Scalar multiplication is equivalent to the repeated application of the group operation on
an element `A` with itself `r-1` times, denoted as `ScalarMult(A, r)`. For any element `A`, `ScalarMult(A, p) = I`.
We denote `B` as a fixed generator of the group. Scalar base multiplication is equivalent to the repeated application
of the group operation `B` with itself `r-1` times, this is denoted as `ScalarBaseMult(r)`.

This document uses the `Element` type to denote elements of the group `G`, and `Scalar` type to
represent elements of the corresponding finite field. We denote Scalar(x) as the conversion
of integer input `x` to the corresponding Scalar value with the same numeric value. For example,
Scalar(1) yields a Scalar representing the value 1.

We now detail a number of member functions that can be invoked on `G`.

- Identity(): Outputs the identity `Element` of the group (i.e. `I`).
- ScalarMult(A, k): Output the scalar multiplication between Element `A` and Scalar `k`.
- ScalarBaseMult(k): Output the scalar multiplication between Scalar `k` and the group generator `B`.
- SerializeElement(A): Maps an `Element` `A` to a canonical byte array `buf` of fixed length `Nelement`. This
  function can raise an error if `A` is the identity element of the group.
- DeserializeElement(buf): Attempts to map a byte array `buf` to an `Element` `A`,
  and fails if the input is not the valid canonical byte representation of an element of
  the group. This function can raise an error if deserialization fails
  or `A` is the identity element of the group.

### Group Ristretto255

This named group has prime order 2^252 + 27742317777372353535851937790883648493 (see {{RISTRETTO}}).
It is implemented as follows.

- Identity(): As defined in {{RISTRETTO}}.
- SerializeElement(A): Implemented using the 'Encode' function from {{RISTRETTO}}.
  Additionally, this function validates that the input element is not the group
  identity element.
- DeserializeElement(buf): Implemented using the 'Decode' function from {{RISTRETTO}}.
  Additionally, this function validates that the resulting element is not the group
  identity element.

# Helper Functions {#helpers}

This section describes operations on and associated with polynomials over Scalars
that are used for secret sharing. A polynomial of maximum degree t+1 is represented
as a list of t coefficients, where the constant term of the polynomial
is in the first position and the highest-degree coefficient is in the last position.
A point on the polynomial is a tuple (x, y), where `y = f(x)`. For notational
convenience, we refer to the x-coordinate and y-coordinate of a
point p as `p.x` and `p.y`, respectively.

## Polynomial coefficient derivation

This section describes a method for deriving a polynomial coefficients based on a secret value
and randomness as input. The function is implicitly parameterized by a field F.

~~~
  poylnomial_coefficients(zero_coefficient, coefficient_rand, threshold):

  Inputs:
  - zero_coefficient, secret value for the 0-th coefficient
  - coefficient_rand, randomness for deriving the remaining coefficients
  - threshold, the number of coefficients to derive

  Outputs:
  - base, the encoded secret associated with the polynomial
  - poly, a list of coefficients representing the polynomial, starting from 0 in increasing order

  def poylnomial_coefficients(zero_coefficient, coefficient_rand, t):
    base = F.HashToScalar(zero_coefficient, str(t) || "-" || str(0))
    poly = [base]
    for i in range(1, t):
      poly.extend(F.HashToScalar(rand, str(t) || "-" || str(i)))
    return F.SerialieScalar(base), poly
~~~

## Evaluation of a polynomial

This section describes a method for evaluating a polynomial `f` at a
particular input `x`, i.e., `y = f(x)` using Horner's method.

~~~
  polynomial_evaluate(x, coeffs):

  Inputs:
  - x, input at which to evaluate the polynomial, a Scalar
  - coeffs, the polynomial coefficients, a list of Scalars

  Outputs: Scalar result of the polynomial evaluated at input x

  def polynomial_evaluate(x, coeffs):
    value = 0
    for coeff in reverse(coeffs):
      value *= x
      value += coeff
    return value
~~~

## Lagrange coefficients

The function `derive_lagrange_coefficient` derives a Lagrange coefficient
to later perform polynomial interpolation, and is provided a list of x-coordinates
as input. Note that `derive_lagrange_coefficient` does not permit any x-coordinate
to equal 0. Lagrange coefficients are used in FROST to evaluate a polynomial `f`
at x-coordinate 0, i.e., `f(0)`, given a list of `t` other x-coordinates.

~~~
  derive_lagrange_coefficient(x_i, L):

  Inputs:
  - x_i, an x-coordinate contained in L, a Scalar
  - L, the set of x-coordinates, each a Scalar

  Outputs: L_i, the i-th Lagrange coefficient

  Errors:
  - "invalid parameters", if 1) any x-coordinate is equal to 0, 2) if x_i
    is not in L, or if 3) any x-coordinate is represented more than once in L.

  def derive_lagrange_coefficient(x_i, L):
    if x_i == 0:
      raise "invalid parameters"
    for x_j in L:
      if x_j == 0:
        raise "invalid parameters"
    if x_i not in L:
      raise "invalid parameters"
    for x_j in L:
      if count(x_j, L) > 1:
        raise "invalid parameters"

    numerator = Scalar(1)
    denominator = Scalar(1)
    for x_j in L:
      if x_j == x_i: continue
      numerator *= x_j
      denominator *= x_j - x_i

    L_i = numerator / denominator
    return L_i
~~~

# Unverifiable Threshold Secret Sharing {#tss}

An unverifiable threshold secret sharing scheme, denoted TSS, consists of two phases: secret
splitting, run by clients, and secret recovery, run by aggregators. Secret splitting takes as input a secret,
randomness, and a threshold, and uses it to produce a shared secret and one or more shares that
can be combined to recover the shared secret. The splitting phase is shown below.

~~~
             +---------+
   Secret --->   TSS   +-----> Share 1, Share 2, ...
Randomness -->  Split  +-----> Shared secret
             +---------+
~~~
{: #split-procedure title="TSS splitting procedure"}

Secret recover involves the combination of at least the threshold number of secret shares
to produce the shared secret derived from the splitting phase. This is shown below.

~~~
Share 1   Share 2   ..   Share t
    |          |             |
    |          |             |    +-----------+
    |          |             +--->|    TSS    |
    |          +----------------->|  Recover  +--> Shared Secret
    +---------------------------->+-----------+
~~~
{: #recover-procedure title="TSS recover procedure"}

The syntax of the splitting and recover phases in the TSS scheme is below:

- SplitAt(k, secret, rand, x): Produce a `k`-threshold share of `secret` using randomness `rand` for the
  target Scalar x, as well as an encoding of the shared secret. The value `k` is an integer, `secret`
  and `rand` are byte strings, and `x` is a Scalar.
- RandomSplit(k, secret, rand): Produce a random `k`-threshold share of `secret` using randomness `rand`,
  as well as an encoding of the shared secret. The share is a `Nshare`-byte string, and the shared
  secret is a `Nsecret`-byte string. The value `k` is an integer, and `secret`  and `rand` are byte strings.
- Recover(k, share_set): Combine the secret shares in `share_set`, which is of size at least
  `k`, and recover the shared secret output from the corresponding RandomShare or Share function.
  If recovery fails, this function returns an error.

In the rest of this section, we describe how to implement these functions for the TSS scheme.

## Construction

A TSS scheme is parameterzed by a field F that implements the abstraction described in {{dep-field}}.
Using F, the RandomSplit, SplitAt, and Recover functions are implemented as follows.

~~~~~
def SplitAt(threshold, secret, rand, x):
  # Construct the secret sharing polynomial
  base, poly = poylnomial_coefficients(secret, rand, threshold)

  # Evaluate the polynomial at the desired point
  y = polynomial_evaluate(x, poly)

  # Construct the share
  x_enc = G.SerializeScalar(x)
  y_enc = G.SerializeScalar(y)
  share = x_enc || y_enc

  return base, share

def RandomSplit(k, secret, rand):
  x = F.RandomScalar()
  return SplitAt(k, secret, rand, x)

def Recover(threshold, share_set):
  if share_set.length < threshold:
    raise RecoveryFailedError

  points = []
  for share in share_set:
    x = F.DeserializeScalar(share[0:SCALAR_SIZE])
    y = F.DeserializeScalar(share[SCALAR_SIZE:])
    points.append((x, y))

  poly = polynomial_interpolation(points)
  base = poly[0]
  return F.SerializeScalar(base)
~~~~~

# Verifiable Threshold Secret Sharing {#vtss}

A verifiable threshold secret sharing scheme, denoted VTSS, is similar to a TSS scheme
but with the additional property that each share can be verified for consistency with the
underlying secret. This property lets the aggregator check that the share is correct.
Like the TSS scheme, a VTSS scheme consists of three phases: secret splitting, run by clients,
share verification, run by aggregators, and secret recovery, run by aggregators. Secret
splitting and recovery are as described in {{tss}}. Share verification takes as input a share
and decides whether or not the share is valid, as shown below.

~~~
        +-------------+
Share --> VTSS Verify +---> Valid?
        +-------------+
~~~
{: #verification-procedure title="VTSS verifiation procedure"}

Each share is verified with a corresponding commitment. A VTSS scheme allows an aggregator
to extract an encoding of the commitment from a share. This can be used, for example, to
group shares that have matching commitment values. Note that not all VTSS schemes will
produce secret shares with matching commitments when run on the same inputs.

VTSS extends the syntax of a TSS scheme with new functions that support share verification,
described below:

- VerifyShare(share): Output 1 if the share is valid and 0 otherwise.
- ShareCommitment(share): Outputs a commitment corresponding to the share.

The rest of this section describes how to construct a VTSS scheme.

## Construction

A VTSS scheme is parameterzed by a prime-order group G that implements the abstraction described in {{dep-pog}}.
The VTSS scheme in this section is based on Feldman's scheme from {{Feldman}}.
In particular, using G, the RandomSplit, SplitAt, and Recover functions are implemented as follows.

[[OPEN ISSUE: Should we specify Pedersen secret sharing here?]]

~~~~~
def RandomShare(k, secret, rand):
  # Evaluate the polynomial at a random point
  x = G.RandomScalar()
  return SplitAt(k, secret, rand, x)

def SplitAt(k, secret, rand, x):
  # Construct the secret sharing polynomial
  poly = poylnomial_coefficients(secret, rand, k)

  # Compute the secret (and polynomial) commitment
  commitment = Commit(secret)

  # Evaluate the polynomial at the desired point
  y = polynomial_evaluate(x, poly)

  # Construct the share
  x_enc = G.SerializeScalar(x)
  y_enc = G.SerializeScalar(y)
  share = x_enc || y_enc || commitment

  return share

def Recover(k, share_set):
  if share_set.length < k:
    raise RecoveryFailedError

  points = []
  for share in share_set:
    if VerifyShare(share) == 0:
      raise "invalid share"
    x = G.DeserializeScalar(share[0:SCALAR_SIZE])
    y = G.DeserializeScalar(share[SCALAR_SIZE:2*SCALAR_SIZE])
    points.append((x, y))

  poly = polynomial_interpolation(points)
  return poly[0]
~~~~~

The helper functions `polynomial_evaluate` and `polynomial_interpolation` are as defined
in {{helpers}}. The helper function Commit is implemented as follows:

~~~~~
def Commit(poly):
  commitment = nil
  for coefficient in poly:
    C_i = G.ScalarBaseMult(coefficient)
    commitment = commitment || G.SerializeElement(C_i)
  return commitment
~~~~~

VerifyShare is implemented as follows.

~~~~~
def Verify(share):
  x = G.DeserializeScalar(share[0:SCALAR_SIZE])
  y = G.DeserializeScalar(share[SCALAR_SIZE:2*SCALAR_SIZE])
  commitment = share[2*SCALAR_SIZE:]

  S' = G.ScalarBaseMult(y)
  if len(commitment) % Nelement != 0:
    raise "invalid commitment length"
  num_coefficients = len(commitment) % Nelement
  commitments = []
  for i in range(0, num_coefficients):
    c_i = G.DeserializeElement(commitment[i*Nelement:(i+1)*Nelement])
    commitments.extend(c_i)

  S = G.Identity()
  for j in range(0, num_coefficients):
    S = S + G.ScalarMult(commitments[j], pow(x, j))
  return S == S'
~~~~~

Finally, ShareCommitment is implemented as follows.

~~~~~
def ShareCommitment(share):
  commitment = share[2*SCALAR_SIZE:]
  return commitment
~~~~~

# Random Scalar Generation {#random-scalar}

Two popular algorithms for generating a random integer uniformly distributed in
the range \[0, G.Order() -1\] are as follows:

## Rejection Sampling

Generate a random byte array with `Ns` bytes, and attempt to map to a Scalar
by calling `DeserializeScalar` in constant time. If it succeeds, return the
result. If it fails, try again with another random byte array, until the
procedure succeeds. Failure to implement `DeserializeScalar` in constant time
can leak information about the underlying corresponding Scalar.

As an optimization, if the group order is very close to a power of
2, it is acceptable to omit the rejection test completely.  In
particular, if the group order is p, and there is an integer b
such that `p - 2<sup>b</sup>| < 2<sup>(b/2)</sup>`, then
`RandomScalar` can simply return a uniformly random integer of at
most b bits.

## Wide Reduction

Generate a random byte array with `l = ceil(((3 * ceil(log2(G.Order()))) / 2) / 8)`
bytes, and interpret it as an integer; reduce the integer modulo `G.Order()` and return the
result. See {{Section 5 of HASH-TO-CURVE}} for the underlying derivation of `l`.

# Security Considerations

The fundamental property of each TSS scheme is that it satisfies a notion of privacy, meaning
that individual shares reveal nothing unless the specified threshold number of shares are combined
to recover the secret. A VTSS scheme adds an additional property called verifiability, which allows
the aggregator to check that each share is correct. A VTSS scheme also lets the aggregator implement
recovery such that combination of valid shares with the same commitment succeeds with overwhelming
probability.

TODO: add more security consideration discussion

# IANA Considerations

This document has no IANA actions.

--- back

# TSS Test Vectors

This section contains test vectors for the TSS scheme specified in this
document. All `Element` and `Scalar` values are represented in serialized form and
encoded in hexadecimal strings. The secret and randomness inputs to the scheme is
also encoded as a hexadecimal string. The threshold is an integer.

## TSS-F64

~~~
k: 2
secret: 736563726574
randomness: 31965a715fd8e1f71cd08e0cba86095121dff231eb0ceb29a9c8d760a
47a18a0
shares: 1643a84854b9ba35960ed1f1554fe587,0d0d4ce1af5701c713c11c069963
8850,c985b2c8bfb05eae1809cd70c3da5f29
shared_secret: bb712b08c8694626
~~~

## TSS-F128

~~~
k: 2
secret: 736563726574
randomness: 31965a715fd8e1f71cd08e0cba86095121dff231eb0ceb29a9c8d760a
47a18a0
shares: 32caccef9635b3c70513b1e600f87a7b462ba936b28fb639e16d249907cb5
4c7,e0f9454539e3b4ffaea6339c454d044030824bcdd2f3d447eb5fcbb8808682eb,
6968a3551af142937ce86469d06360918019927e7b75e46cb7d1e1563dc07eb1
shared_secret: 83970665868227256dff87b7512f678e
~~~

## TSS-F255

~~~
k: 2
secret: 736563726574
randomness: 31965a715fd8e1f71cd08e0cba86095121dff231eb0ceb29a9c8d760a
47a18a0
shares: 5fedc0ebd0380eb2bad985e678e906eb21ef41ff62b3f3224912986a3f1ed
37db77e53c008deb27343dde3a17c8ee1c8c166415f505479f6d265b8115b4df436,8
b860322d6546611a74ca9b8b1d673f8ac0a60b3a2e9d037f9d67016556bd84c9830ac
bac779880b69b23de49ac967c199e7b324c0fb73b4e1109f097c414b68,970bc9dc08
9d5fc7b9bbe8b272febc1a001a3d3c00d7d45c7369699796f8df0dd1a502169b00fb2
fae71e5181d89b9df9761e2d5d1db7a18866dacc70f6c6f6a
shared_secret: e13228987163ed149053f939d46abcaf4423079b021128685b498b
6c9202d11f
~~~

# VTSS Test Vectors

TODO

# Acknowledgments
{:numbered="false"}

TODO
