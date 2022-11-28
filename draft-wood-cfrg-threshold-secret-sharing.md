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

# Secret Sharing Schemes

In this section we describe different variants of secret sharing scheme. Each scheme
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

Each scheme follows the same two-step pattern on the client for the splitting phase:

1. Set up a secret sharing context on the client.
2. Use the context to produce one or more shares.

The aggregator then runs a recovery function in the recovery phase to combine
some threshold number of shares to produce the shared secret. 

Beyond the basic scheme, there are secret sharing schemes that provide authenticated
shares, i.e., shares that can be verified for correctness by the aggregator prior to
aggregating. Each variant is identified by a one-byte value.

| Mode                     | Value |
|:=========================|:======|
| mode_basic               | 0x00  |
| mode_auth_deterministic  | 0x01  |
| mode_auth_deterministic  | 0x02  |
{: #hpke-modes title="Secret sharing schemes"}

The rest of this section describes some core funtions used by the secret sharing
schemes. Each of the variants are then described in {{variants}}.

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
commitments. Each of these functions takes as input an identifier at which the secret sharing
polynomial was evaluated, as well as its evalutiation output, and produces a unique data
structure for the type of commitment. 

These two functions are implemented as follows.

~~~~~
def Context.RandomCommitment(id, value):
  random_secret = G.RandomScalar()
  random_seed = random(32)

  inner_splitter = SetupSplitter(self.mode, self.threshold, random_secret, random_seed)
  value = inner_splitter.Split(id)
  
  random_commitment = []
  for coefficient in inner_splitter.poly:
    C_i = G.ScalarBaseMult(coefficient)
    random_commitment.append(C_i)
  return (random_value, random_commitment)

def Context.DeterministicCommitment(id, value):
  commitment = []
  for coefficient in self.poly:
    C_i = G.ScalarBaseMult(coefficient)
    commitment.append(C_i)
  return commitment
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
def VerifyRandomCommitment(id, value, commitment):
  random_value, random_commitments = commitment
  S' = G.ScalarBaseMult(value) + G.ScalarBaseMult2(random_value)
  S = G.Identity()
  for C_i in random_commitments:
    S = S + G.ScalarMult(C_i, pow(id, j))
  return S == S'

def VerifyDeterministicCommitment(id, value, commitment):
  S' = G.ScalarBaseMult(value)
  S = G.Identity()
  for C_i in commitment:
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

# Authenticated Threshold Secret Sharing with Random Tags {#rvtss}

An authenticated threshold secret sharing scheme with random tags, denoted RVTSS, is parameterzed by a
prime-order group G and its scalar field F that implements the abstraction described in {{dep-pog}}. 
The RVTSS scheme in this section is based on Pedersen's scheme from {{Pedersen}}. In particular,
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

# Authenticated Threshold Secret Sharing with Deterministic Tags {#dvtss}

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
randomness: b055db47e17ac19514ec6cca935d274e2a34e4e2478d5eb5adbe686cc
7565eb0
shares: b3b155caa4f41631c0b52a5c58f47981,3d62640c0a7c0bbf2d9682ae58dd
d06a,9c411a0e85cc2e904a82a8090c8ae7d7
shared_secret: 2c419ee80137601e
~~~

## TSS-F128

~~~
k: 2
secret: 736563726574
randomness: b055db47e17ac19514ec6cca935d274e2a34e4e2478d5eb5adbe686cc
7565eb0
shares: e664b0486e16c84388c76c04b554966c556edae4efb99e591dc0a6430f4cc
d45,a328ba43f65d10bdcafc320d76bbe27e0978a2eed06bc2afc635f08755bac8d1,
c6d5999a407dec33539908d01acee070d82753e2bae212f02c0e1aabd4a7c045
shared_secret: 1f0d291badfa38ac623f5b14cb1d7fe4
~~~

## TSS-F255

~~~
k: 2
secret: 736563726574
randomness: b055db47e17ac19514ec6cca935d274e2a34e4e2478d5eb5adbe686cc
7565eb0
shares: 2766662e4bb36ca2b5a7e601e911b09a9790694a2b9ee625d0ceb1a5bc51b
10a41419795f5284e36e2f1ea72dffd37e89d0cfca408f3d7bfd9f2baffb4349a71,0
7689f9149db7635a3e1fec42262eddc27333f5d2a3bdac43370258bc7a4e16dac9f8f
8d384ab607522b4065fd965fadfb21600dfbf21431c50d4558556a8645,b6b12bfa4f
1ff5778d9c01b4c8098ab96387bcc3865cf84cadd407a476befd48c015435c5edd031
3bb72baab7a1d2fdb1b08ed5132c1a2d584a661271de0e25f
shared_secret: e80914f27385ef7275d1d28192086dccbb520388e0fba09ba9dd25
6ef6ca9041
~~~

## VTSS-Ristretto255

~~~
k: 2
secret: 736563726574
randomness: 88297b32dd186d7bbe2ab1756c6b61e3249446c46782b8ff3e5e33abc
f53994d
shares: 410e3cbb47559f739bcd086fa2e7d51b73f4a0b1e5d5041cd8f19affb5f8d
4050d1bd82eb27aa5b808e53b276820def5d9b483bfbf5000aec0d94ea78f1d77077a
331be0e10573245013bdf7203cad5205f6c995ccccfdc3a4d3b91b153ee23d80cfe4e
ce3856f352c19eeac35999f00b3d1501c74885c786e25f7d4d93eb225,02c0c21c383
dc17516f54c710cddad3d733d83ab24129275762673e619e9b10d0066952fa1ab465e
e8087963dd964dac293198aead5c4f7b8df7f130291d3f097a331be0e10573245013b
df7203cad5205f6c995ccccfdc3a4d3b91b153ee23d80cfe4ece3856f352c19eeac35
999f00b3d1501c74885c786e25f7d4d93eb225,172307887a9af71f052b507346ac56
a742a03af554e65c1a51ba505ff76ba501b3de2e9c252a4512ff7a8af72b33dfe4dc7
ee85b7586b7bf8d142cf18ba5d8017a331be0e10573245013bdf7203cad5205f6c995
ccccfdc3a4d3b91b153ee23d80cfe4ece3856f352c19eeac35999f00b3d1501c74885
c786e25f7d4d93eb225
shared_secret: 28e3c7a92b34b0992415f6dcc7fc59fe833b138c78d27399b557e9
4ecbf90103
~~~

# Acknowledgments
{:numbered="false"}

This document was written based on discussions in the Privacy Preserving Measurement Working Group.
