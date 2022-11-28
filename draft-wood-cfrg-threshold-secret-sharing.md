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

### Field FCurve25519

This named field uses MODULUS=2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed with SCALAR_SIZE=32.
It is the scalar field for the Curve25519 elliptic curve. The implementation of
the field functions defined in {{dep-field}} is as follows.

- HashToScalar(x, ctx): Implemented by computing SHA-512("FCurve25519" \|\| DST \|\| x) and mapping the
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
- Commitment(x, r): Output a random Pedersen commitment {{?Pedersen=DOI.10.1007/3-540-46766-1_9}} for
  Scalar inputs `x` and `r`. This function uses a second generator for computing the commitment, where
  the generator is defined as part of the group.

### Group Ristretto255

This named group has prime order 2^252 + 27742317777372353535851937790883648493 (see {{RISTRETTO}}), using
FCurve25519 as the underlying scalar finite field. The implementation of the group functions defined
in {{dep-pog}} is as follows.

- Identity(): As defined in {{RISTRETTO}}.
- SerializeElement(A): Implemented using the 'Encode' function from {{RISTRETTO}}.
  Additionally, this function validates that the input element is not the group
  identity element.
- DeserializeElement(buf): Implemented using the 'Decode' function from {{RISTRETTO}}.
  Additionally, this function validates that the resulting element is not the group
  identity element.
- Commitment(x, r): Implemented by computing the sum of G.ScalarBaseMult(x) and
  G.ScalarMult(B2, r), where B2 is the second group generator defined below.

The encoding of the second generator B2 is d2ac2cd93039618e1ffaebdb5df9044eb6ebc8aa9d47d61ab1d45338f3c18d53.

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
  derive_poylnomial_coefficients(zero_coefficient, coefficient_rand, threshold, ctx):

  Inputs:
  - zero_coefficient, secret value for the 0-th coefficient
  - coefficient_rand, randomness for deriving the remaining coefficients
  - threshold, the number of coefficients to derive
  - ctx, a one-byte context identifier for the polynomial

  Outputs:
  - base, the encoded secret associated with the polynomial
  - poly, a list of coefficients representing the polynomial, starting from 0 in increasing order

  def derive_poylnomial_coefficients(zero_coefficient, coefficient_rand, t):
    base = F.HashToScalar(zero_coefficient, ctx || "-" || str(t) || "-" || str(0))
    poly = [base]
    for i in range(1, t):
      poly.extend(F.HashToScalar(rand, ctx || "-" || str(t) || "-" || str(i)))
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

# Secret Sharing Overview

In this section we describe different variants of secret sharing scheme. Each variant
consists of two phases: secret splitting, run by clients, and secret recovery, run
by aggregators. Secret splitting takes as input a secret, randomness, and a threshold,
and uses it to produce a shared secret and one or more shares that can be combined
to recover the shared secret. The splitting phase is shown below.

~~~
             +---------+
   Secret ---> Secret  +-----> Share 1, Share 2, ...
Randomness -->  Split  +-----> Shared secret
             +---------+
~~~
{: #split-procedure title="Secret splitting procedure"}

Secret recovery involves the combination of at least the threshold number of secret shares
to produce the shared secret derived from the splitting phase. This is shown below.

~~~
Share 1   Share 2   ..   Share t
    |          |             |
    |          |             |    +-----------+
    |          |             +--->|  Secret   |
    |          +----------------->|  Recover  +--> Shared Secret
    +---------------------------->+-----------+
~~~
{: #recover-procedure title="Secret recover procedure"}

Each variant follows the same two-step pattern on the client for the splitting phase:

1. Set up a secret sharing context on the client.
2. Use the context to produce one or more shares.

The aggregator then runs a recovery function in the recovery phase to combine
some threshold number of shares to produce the shared secret.

Beyond the basic variant, there are secret sharing schemes that provide authenticated
shares, i.e., shares that can be verified for correctness by the aggregator prior to
aggregating. These variants are referred to as verifiable secret sharing schemes.

Each variant is identified by a one-byte value.

| Mode                     | Value |
|:=========================|:======|
| mode_basic               | 0x00  |
| mode_auth_deterministic  | 0x01  |
| mode_auth_random         | 0x02  |
{: #hpke-modes title="Secret sharing schemes"}

Each of the variants are then described in {{variants}}.

# Core Functions

This section describes some of the core functions used for building secret
sharing variants.

## Splitter Functions

The splitting phase requries establishment of a context. This context takes
as input the secret value `secret` to share, the randomness `rand` to use
for deriving shares, and the desired threshold of the shares. The context
then consists of the internal poylnomial used for producing shares, as well
as the shared secret associated with each share.

Construction of the context is done as follows:

~~~~~
def SetupSplitter(mode, threshold, secret, rand):
  shared_secret, poly = derive_poylnomial_coefficients(secret, rand, threshold, mode)
  return SplitterContext(mode, threshold, shared_secret, poly)
~~~~~

The splitter context can then be used to produce shares evaluated at specific points
on the polynomial. In particular, the context has a function for evaluating the
secret sharing polynomial on the input Scalar `id` and producing the corresponding output.
This function is implemented as follows

~~~~~
def Context.Split(id):
  value = polynomial_evaluate(id, self.poly)
  return value
~~~~~

For authenticated variants, the splitter context can also be used to produce commitments
to the underlying secret. This document defines two types of commitments: random and deterministic
commitments. Deterministic commitments consist of a list of Element values and can be
produced from the context directly and do not vary based on the share produced, as described below.

~~~~~
def Context.DeterministicCommitment():
  commitment = []
  for coefficient in self.poly:
    C_i = G.ScalarBaseMult(coefficient)
    commitment.append(C_i)
  return commitment
~~~~~

Random commitments require the identifier at which the secret sharing polynomial was evaluated
and produces a tuple of values corresponding to the commitment, as described below.

~~~~~
def Context.RandomCommitment(id):
  random_secret = random(32)
  random_seed = random(32)

  inner_splitter = SetupSplitter(self.mode, self.threshold, random_secret, random_seed)
  value = inner_splitter.Split(id)

  random_commitments = []
  for coefficient in range(self.threshold):
    C_i = G.Commitment(self.poly[i], inner_splitter.poly[i])
    random_commitments.append(C_i)
  return (random_value, random_commitments)
~~~~~

Commitments can be serialized and deserialized from their unique data structures to
byte strings using for transmission between clients and aggregators. The following two
functions describe how to serialize and deserialize deterministic commitments. Note that
the deserialization function is fallible for invalid inputs, i.e., inputs of the wrong
length or with invalid Element encodings.

~~~~~
SerializeDeterministicCommitment(commitment):
  commitment = nil
  for C_i in commitment:
    commitment = commitment || G.SerializeElement(C_i)
  return commitment

DeserializeDeterministicCommitment(commitment):
  if len(commitment) % Nelement != 0:
    raise "invalid input"
  num_coefficients = len(commitment) % Nelement
  commitments = []
  for i in range(0, num_coefficients):
    c_i = G.DeserializeElement(commitment[i*Nelement:(i+1)*Nelement])
    commitments.extend(c_i)
  return commitments
~~~~~

Similarly, the following two functions describe how to serialize and deserialize random
commitments. Note that the deserialization function is fallible for invalid inputs, i.e.,
inputs of the wrong length or with invalid Element encodings.

~~~~~
SerializeRandomCommitment(commitment):
  random_value, random_commitments = commitment
  commitment = F.SerializeScalar(random_value)
  for C_i in random_commitments:
    commitment = commitment || G.SerializeElement(C_i)
  return commitment

DeserializeRandomCommitment(commitment):
  if len(commitment) < Nscalar:
    raise "invalid input"
  random_value = F.DeserializeScalar(commitment[:Nscalar])

  if len(commitment[Nscalar:]) % Nelement != 0:
  num_coefficients = len(commitment[Nscalar:]) % Nelement
  random_commitments = []
  for i in range(0, num_coefficients):
    c_i = G.DeserializeElement(commitment[Nscalar+i*Nelement:Nscalar+(i+1)*Nelement])
    random_commitments.extend(c_i)
  return (random_value, random_commitments)
~~~~~

## Recovery Functions

The basic recovery phase consists of a single function:

- Combine(k, share_set): Aggregate the secret shares in `share_set`, which is of size at least
  `k`, and recover the shared secret output from the corresponding RandomShare or Share function.
  If recovery fails, this function returns an error.

This function is implemented as follows.

~~~~~
def Combine(threshold, points):
  if points.length < threshold:
    raise RecoveryFailedError

  poly = polynomial_interpolation(points)
  shared_secret = F.SerializeScalar(poly[0])
  return shared_secret
~~~~~

For authenticated variants, the recovery phase also requires verifying random or deterministic
share commitments produced during the splitting phase. Verification is done using one of
the two following functions.

~~~~~
def VerifyRandomCommitment(id, value, random_commitment):
  random_value, random_commitments = random_commitment
  S' = G.ScalarBaseMult(value) + G.ScalarBaseMult2(random_value)
  S = G.Identity()
  for C_i in random_commitments:
    S = S + G.ScalarMult(C_i, pow(id, j))
  return S == S'

def VerifyDeterministicCommitment(id, value, det_commitment):
  S' = G.ScalarBaseMult(value)
  S = G.Identity()
  for C_i in det_commitment:
    S = S + G.ScalarMult(C_i, pow(id, j))
  return S == S'
~~~~~

# Secret Sharing Variants {#variants}

This section describes the secret sharing variants. Each scheme has the basic syntax:

- Share(k, secret, rand, n): Produce `n` `k`-threshold shares of `secret` using randomness `rand` for the
  target Scalar x, as well as an encoding of the shared secret. The value `k` is an integer, `secret`
  and `rand` are byte strings, `x` is a Scalar, and `n` is a positive integer at least as large as `k`.
  The output is a list of `n` byte strings.
- RandomShare(k, secret, rand): Produce a random `k`-threshold share of `secret` using randomness `rand`,
  as well as an encoding of the shared secret. The share is a `Nshare`-byte string, and the shared
  secret is a `Nsecret`-byte string. The value `k` is an integer, and `secret`  and `rand` are byte strings.
- Recover(k, share_set): Combine the secret shares in `share_set`, which is of size at least
  `k`, and recover the shared secret output from the corresponding RandomShare or Share function.
  If recovery fails, this function returns an error.

The authenticated variants extend this syntax with two new functions:

- Verify(share): Output 1 if `share` is valid and 0 otherwise, where `share` is a byte string
  output from Share or RandomShare.
- ShareCommitment(share): Outputs a byte-string `commitment` corresponding to the share, where `share`
  is a byte string output from Share or RandomShare.

The rest of this section describes the different secret sharing variants.

## Basic Threshold Secret Sharing {#tss}

The basic threshold secret sharing scheme, denoted TSS, is parameterzed by a field F
that implements the abstraction described in {{dep-field}}. Using F, the RandomShare,
Share, and Recover functions are implemented as follows.

~~~~~
def Share(threshold, secret, rand, id):
  context = SetupSplitter(mode_basic, secret, rand, threshold)

  value = context.Split(id)

  # Serialize the share
  id_enc = G.SerializeScalar(id)
  value_enc = G.SerializeScalar(value)
  share = id_enc || value_enc

  return context.shared_secret, share

def RandomShare(k, secret, rand):
  x = F.RandomScalar()
  return Share(k, secret, rand, x)

def Recover(threshold, share_set):
  if share_set.length < threshold:
    raise RecoveryFailedError

  points = []
  for share in share_set:
    x = F.DeserializeScalar(share[0:SCALAR_SIZE])
    y = F.DeserializeScalar(share[SCALAR_SIZE:])
    points.append((x, y))

  return Combine(points)
~~~~~

## Authenticated Threshold Secret Sharing with Random Tags {#rvtss}

An authenticated threshold secret sharing scheme with random tags, denoted RVTSS, is parameterzed by a
prime-order group G and its scalar field F that implements the abstraction described in {{dep-pog}}.
The RVTSS scheme in this section is based on Pedersen's scheme from {{?Pedersen=DOI.10.1007/3-540-46766-1_9}}. In particular,
using G and F, the RandomShare, Share, and Recover functions are implemented as follows.

~~~~~
def Share(k, secret, rand, x):
  context = SetupSplitter(mode_basic, secret, rand, threshold)

  value = context.Split(id)
  commitment = context.RandomCommitment(id, poly)

  # Construct the share
  id_enc = G.SerializeScalar(id)
  value_enc = G.SerializeScalar(value)
  commitment_enc = SerializeRandomCommitment(commitment)
  share = id_enc || value_enc || commitment_enc

  return share

def RandomShare(k, secret, rand):
  # Evaluate the polynomial at a random point
  x = F.RandomScalar()
  return Share(k, secret, rand, x)

def Recover(k, share_set):
  if share_set.length < k:
    raise RecoveryFailedError

  points = []
  for share in share_set:
    if Verify(share) == 0:
      raise "invalid share"
    x = F.DeserializeScalar(share[0:SCALAR_SIZE])
    y = F.DeserializeScalar(share[SCALAR_SIZE:2*SCALAR_SIZE])
    points.append((x, y))

  return Combine(points)
~~~~~

Verify is implemented as follows.

~~~~~
def Verify(share):
  id = G.DeserializeScalar(share[0:SCALAR_SIZE])
  value = G.DeserializeScalar(share[SCALAR_SIZE:2*SCALAR_SIZE])
  commitment_enc = share[2*SCALAR_SIZE:]

  commitments = DeserializeRandomCommitment(commitment_enc)

  return VerifyRandomCommitment(id, value, commitments)
~~~~~

Finally, ShareCommitment is implemented as follows.

~~~~~
def ShareCommitment(share):
  commitment = share[2*SCALAR_SIZE:]
  return commitment
~~~~~

## Authenticated Threshold Secret Sharing with Deterministic Tags {#dvtss}

An authenticated threshold secret sharing scheme with deterministic tags, denoted DVTSS, is parameterzed by a
prime-order group G and its scalar field F that implements the abstraction described in {{dep-pog}}.
The DVTSS scheme in this section is based on Feldman's scheme from {{Feldman}}. In particular,
using G and F, the RandomShare, Share, and Recover functions are implemented as follows.

~~~~~
def Share(k, secret, rand, x):
  context = SetupSplitter(mode_basic, secret, rand, threshold)

  value = context.Split(id)
  commitment = context.DeterministicCommitment(id, poly)

  # Construct the share
  id_enc = G.SerializeScalar(id)
  value_enc = G.SerializeScalar(value)
  commitment_enc = SerializeDeterministicCommitment(commitment)
  share = id_enc || value_enc || commitment_enc

  return share

def RandomShare(k, secret, rand):
  # Evaluate the polynomial at a random point
  x = F.RandomScalar()
  return Share(k, secret, rand, x)

def Recover(k, share_set):
  if share_set.length < k:
    raise RecoveryFailedError

  points = []
  for share in share_set:
    if VerifyShare(share) == 0:
      raise "invalid share"
    x = F.DeserializeScalar(share[0:SCALAR_SIZE])
    y = F.DeserializeScalar(share[SCALAR_SIZE:2*SCALAR_SIZE])
    points.append((x, y))

  return Combine(points)
~~~~~

Verify is implemented as follows.

~~~~~
def Verify(share):
  id = G.DeserializeScalar(share[0:SCALAR_SIZE])
  value = G.DeserializeScalar(share[SCALAR_SIZE:2*SCALAR_SIZE])
  commitment_enc = share[2*SCALAR_SIZE:]

  commitments = DeserializeDeterministicCommitment(commitment_enc)

  return VerifyDeterministicShare(id, value, commitments)
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

# Test Vectors

This section contains test vectors for the TSS and VTSS schemes specified in this
document. All `Element` and `Scalar` values are represented in serialized form and
encoded in hexadecimal strings. The secret and randomness inputs to the scheme is
also encoded as a hexadecimal string. The threshold is an integer.


## TSS-F64

~~~
k: 2
secret: 736563726574
randomness: 1e325dc577261c977ea0faa042202e1ff3b3ea913f6530b1a4b19b58b
ed31205
shares: 56a3270beed985df81b13a5388fa5e52,beb1de321d43cf0da058d206e642
3b9f,d9d903d1c76a850201aab431d37ae8f0
shared_secret: fc3a9e517170d3d3
~~~

## TSS-F128

~~~
k: 2
secret: 736563726574
randomness: 1e325dc577261c977ea0faa042202e1ff3b3ea913f6530b1a4b19b58b
ed31205
shares: fef4c962e1c956bacc957b5cedcd9d748039bc3adb5e8e1fec97bda00c444
62c,c27808d82207cca5ab6f0e20b790afaac3e34be725664badc43a093b4d493327,
6995a7a17e03fb0b8a4970c43b40d83500ad27f8fbe0da42bf1e8f92f072a9f3
shared_secret: 09d3b1b0f9be9f530d2cd11f0bda2cac
~~~

## TSS-F255

~~~
k: 2
secret: 736563726574
randomness: 1e325dc577261c977ea0faa042202e1ff3b3ea913f6530b1a4b19b58b
ed31205
shares: 814fd00076499894fdf3c06f8aedcfab15f3e76b52ef349c29b10a4d15ae0
51352999b4d14dcb1ef0e5620ebe0f23dbd1b8bb77b6cc74285aaa99e35716ec327,a
c7b6a997d2da53114ab01ac1fbf9b97ed0955ee0a9f227a9ee1195fb6415836361c18
cd2038a5aa755980ba4443e58fd6114807e6e4f57af0542a16cbf59815,8c5cc8412e
42b8ee80ce3fa1b96a88601e80abc943e5dcac49ee73bf12cd5d6e5d8d64198ea0804
0d3b1e5582f00b6ee7c1190f61af958fea94cbcdef39c3470
shared_secret: 8f1e2d14d4d00e83035c60183e081756d02e29ed2cc6894e79bf2c
8bde0e310e
~~~

## DVTSS-Ristretto255

~~~
k: 2
secret: 736563726574
randomness: a8db8264b6851cf3f945d1a5e6e17ef56b0570d235e43827ef81b3a98
0c3188a
shares: 43a380a9f0ddca73b64869fad8d9eb4b9ff4a669673a623416ef7d0afccc1
904082ae9339424b93a551ebbf7ce83b575b5de3572a9e29bcf0a357bd5a4ed810ba4
9955528f18cd06302513f9aa9be748618600fcdaef202b8583c2210bb7cb5928fd4f6
1e83d3f9c3ae0e38a1d2fb005c2a85a726f126078e701edbc5d9abc2e,48dad15cbd1
1c4c0e432580e75730bb1d9bdab11cfe818ca335a48d014ae1700af230ad59ff4d1f6
de4890f599a96803fd229bec835da9561d6bc247f6b8110ea49955528f18cd0630251
3f9aa9be748618600fcdaef202b8583c2210bb7cb5928fd4f61e83d3f9c3ae0e38a1d
2fb005c2a85a726f126078e701edbc5d9abc2e,1933bda2ed278bbfc3c3c47c248d67
0de560280b5c9934b6020ac704c316ae06629dbda78e9f1476552e6ea37e6759f8de4
16440643a5ddad0bfcd75a11b3606a49955528f18cd06302513f9aa9be748618600fc
daef202b8583c2210bb7cb5928fd4f61e83d3f9c3ae0e38a1d2fb005c2a85a726f126
078e701edbc5d9abc2e
shared_secret: edb875686b330f37883f51332cbdd80f38ab8d5bbeab332a1a0685
5a12394e0f
~~~

## RVTSS-Ristretto255

~~~
k: 2
secret: 736563726574
randomness: 2f6c33f327f3ddcadd29588d332a8470801928fe83983b2a192d06d81
f0c9b3d
shares: f20ae83b5215b90b416e11924a80920608ae8cfe6a06657ffc01c220cf004
200a1f6ca25d818965a7072cc4f63c322e2e1d82021aed7440c98fbe22278b5710bbd
4155cd1f89a9289691dadd9a0aac3d1c2f2963192c3aa4d5b54774b307a20f3231686
1dd8f2b41193a62dd9c8ab23803a341071ad1dcd4e939986ff335b247ac0e31f8c110
28db0d70637fdd98d6cc19855bad73dbfc8a5a1a0931059c745f,c125d9e4877d7179
dd78c62d0e095110b4a29bc309462cf223e2162a1da19f0ab038300634619cc355fe8
ce730206ece96fd7709902771d0785ab9ad1ffac708ffd66f17a114a0e8bc870d89bc
770ec688a9b58c81ed021546b89ab987ddc00e06fe5f6311c01faa1021b588967e186
cfa71c69202ff414be8570249f1a6b84edcb3d493b4172973a2a866d356e4dc8c1a4a
caa0c809a4a0fbf7f53d916fea26,131fdedb6cbf84844f713659e62f0876109cbe23
0f5418d8e26503d8c2022801c1ff583ec2e750e3d4c6a6a253c84802f6b7ad06a06f7
a077667e3d188f3af0f19531aec9468c253db4923e97a8160100da7f436c17c6594ce
604ef26c3ec10fbcbfeb75d57dad72778b58c16737ad493b0d1d803893e722974498b
74779ab4c18d2f73b4ee1213be3872f201419046e9df2cfbc547f2115a86958931144
e610
shared_secret: 80e702ce03d835247b31d32c8a87d03aa8212b69bf31568ab0df88
a82c4e8a0b
~~~

# Acknowledgments
{:numbered="false"}

This document was written based on discussions in the Privacy Preserving Measurement Working Group.
