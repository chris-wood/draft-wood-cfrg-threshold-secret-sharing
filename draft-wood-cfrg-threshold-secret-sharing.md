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
secret sharing schemes can be verifiable {{CITE FELDMAN}}, which allows an aggregator to check
that the share is valid. Other schemes allow metadata to be associated with
a secret share and authenticated during secret recovery {{CITE ADSS}}.

This document specifies a simple abstraction for threshold secret sharing
with two different modes: unverifiable and verifiable. We denote TSS and VTSS
as the unverifiable and verifiable modes, respectively.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following notation is used throughout the document.

* `random_bytes(n)`: Outputs `n` bytes, sampled uniformly at random
using a cryptographically secure pseudorandom number generator (CSPRNG).
* `count(i, L)`: Outputs the number of times the element `i` is represented in the list `L`.
* `len(l)`: Outputs the length of input list `l`, e.g., `len([1,2,3]) = 3)`.
* `reverse(l)`: Outputs the list `l` in reverse order, e.g., `reverse([1,2,3]) = [3,2,1]`.
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
Each field also has an associated parameter called `Nscalar`, which is the number of
bytes used to encode a field element as a byte string. 

For convenience, each field has an associated function called `RandomScalar` that
is used to sample a uniformly random Scalar from the field. Refer to {{random-scalar}} 
for implementation guidance.

Each field `F` also has the following encoding and decoding functions:

- HashToScalar(x, DST): TODO
- SerializeScalar(s): Maps a Scalar `s` to a canonical byte array `buf` of fixed length `Nscalar`.
- DeserializeScalar(buf): Attempts to map a byte array `buf` to a `Scalar` `s`.
  This function can raise an error if deserialization fails.

### Field F64

This named field uses MODULUS=2^32 * 4294967295 + 1 with Nscalar=8. The implementation of
the field functions defined in {{dep-field}} is as follows.

- HashToScalar(x, DST): TODO
- SerializeScalar(s): TODO
- DeserializeScalar(buf): TODO

### Field F128

This named field uses MODULUS=2^66 * 4611686018427387897 + 1 with Nscalar=16. The implementation of
the field functions defined in {{dep-field}} is as follows.

- HashToScalar(x, DST): TODO
- SerializeScalar(s): TODO
- DeserializeScalar(buf): TODO

### Field F255

This named field uses MODULUS=2^255 - 19 with Nscalar=32. The implementation of
the field functions defined in {{dep-field}} is as follows.

- HashToScalar(x, DST): TODO
- SerializeScalar(s): Implemented by outputting the little-endian 32-byte encoding of
  the field element value with the top three bits set to zero.
- DeserializeScalar(buf): Implemented by attempting to deserialize a field element from a
  little-endian 32-byte string. This function can fail if the input does not
  represent a Scalar in the range \[0, `G.Order()` - 1\]. Note that this means the
  top three bits of the input MUST be zero.

## Prime-Order Group {#dep-pog}

FROST depends on an abelian group of prime order `p`. We represent this
group as the object `G` that additionally defines helper functions described below. The group operation
for `G` is addition `+` with identity element `I`. For any elements `A` and `B` of the group `G`,
`A + B = B + A` is also a member of `G`. Also, for any `A` in `G`, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. For convenience, we use `-` to denote
subtraction, e.g., `A - B = A + (-B)`. Integers, taken modulo the group order `p`, are called
scalars; arithmetic operations on scalars are implicitly performed modulo `p`. Since `p` is prime,
scalars form a finite field. Scalar multiplication is equivalent to the repeated
application of the group operation on an element `A` with itself `r-1` times, denoted as
`ScalarMult(A, r)`. We denote the sum, difference, and product of two scalars using the `+`, `-`,
and `*` operators, respectively. (Note that this means `+` may refer to group element addition or
scalar addition, depending on types of the operands.) For any element `A`, `ScalarMult(A, p) = I`.
We denote `B` as a fixed generator of the group. Scalar base multiplication is equivalent to the repeated application
of the group operation `B` with itself `r-1` times, this is denoted as `ScalarBaseMult(r)`. The set of
scalars corresponds to `GF(p)`, which we refer to as the scalar field. This document uses types
`Element` and `Scalar` to denote elements of the group `G` and its set of scalars, respectively.
We denote Scalar(x) as the conversion of integer input `x` to the corresponding Scalar value with
the same numeric value. For example, Scalar(1) yields a Scalar representing the value 1.
We denote equality comparison as `==` and assignment of values by `=`. Finally, it is assumed that
group element addition, negation, and equality comparisons can be efficiently computed for
arbitrary group elements.

We now detail a number of member functions that can be invoked on `G`.

- Order(): Outputs the order of `G` (i.e. `p`).
- Identity(): Outputs the identity `Element` of the group (i.e. `I`).
- ScalarMult(A, k): Output the scalar multiplication between Element `A` and Scalar `k`.
- ScalarBaseMult(k): Output the scalar multiplication between Scalar `k` and the group generator `B`.
- SerializeElement(A): Maps an `Element` `A` to a canonical byte array `buf` of fixed length `Nelement`. This
  function can raise an error if `A` is the identity element of the group.
- DeserializeElement(buf): Attempts to map a byte array `buf` to an `Element` `A`,
  and fails if the input is not the valid canonical byte representation of an element of
  the group. This function can raise an error if deserialization fails
  or `A` is the identity element of the group; see {{ciphersuites}} for group-specific
  input validation steps.

### Group Ristretto255

This named group is implemented as follows.

- Order(): Return 2^252 + 27742317777372353535851937790883648493 (see {{RISTRETTO}})
- Identity(): As defined in {{RISTRETTO}}.
- SerializeElement(A): Implemented using the 'Encode' function from {{!RISTRETTO}}.
  Additionally, this function validates that the input element is not the group
  identity element.
- DeserializeElement(buf): Implemented using the 'Decode' function from {{!RISTRETTO}}.
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
  poylnomial_coefficients(zero_coefficient, coefficient_rand, t):

  Inputs:
  - zero_coefficient, secret value for the 0-th coefficient
  - coefficient_rand, randomness for deriving the remaining coefficients
  - t, the number of coefficients to derive

  Outputs: A list of coefficients representing the polynomial, starting from 0 in increasing order

  def poylnomial_coefficients(zero_coefficient, coefficient_rand, t):
    poly = [F.HashToScalar(zero_coefficient, str(t) || "-" || str(0))]
    for i in range(1, t):
      poly.extend(F.HashToScalar(rand, str(t) || "-" || str(i)))
    return poly
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
   Secret
     |      
+----V----+------> Share 1, Share 2, ...
|  Split  |
+----^----+------> Shared Secret
     |      
 Randomness 
~~~
{: #overall-flow title="TSS splitting procedure"}

Secret recover involves the combination of at least the threshold number of secret shares
to produce the shared secret derived from the splitting phase. This is shown below.

~~~
  Share 1   Share 2   ..   Share t
     |          |             |
     |          |             +--->+-----------+  
     |          +----------------->|  Recover  +--> Shared Secret
     +---------------------------->+-----------+  
~~~
{: #overall-flow title="TSS recover procedure"}

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
def SplitAt(k, secret, rand, x):
  # Construct the secret sharing polynomial
  poly = poylnomial_coefficients(secret, rand, k)

  # Evaluate the polynomial at the desired point
  y = polynomial_evaluate(x, poly)

  # Construct the share
  x_enc = G.SerializeScalar(x)
  y_enc = G.SerializeScalar(y)
  share = x_enc || y_enc

  return share

def RandomSplit(k, secret, rand):
  x = F.RandomScalar()
  return SplitAt(k, secret, rand, x)

def Recover(k, share_set):
  if share_set.length < k:
    raise RecoveryFailedError

  points = []
  for share in share_set:
    x = F.DeserializeScalar(share[0:Nscalar])
    y = F.DeserializeScalar(share[Nscalar:])
    points.append((x, y))

  poly = polynomial_interpolation(points)
  return poly[0]
~~~~~

# Verifiable Threshold Secret Sharing {#vtss}

An verifiable threshold secret sharing scheme, denoted VTSS, is similar to a TSS scheme
but with the additional property that each share can be verified for consistency with the
underlying secret. This property lets the aggregator check that the share is correct.
Like the TSS scheme, a VTSS scheme consists of three phases: secret splitting, run by clients, 
share verification, run by aggregators, and secret recovery, run by aggregators. Secret
splitting and recovery are as described in {{tss}}. Share verification takes as input a share
and decides whether or not the share is valid, as shown below.

~~~
   Share
     |      
+----V---+
| Verify |
+----+---+
     |      
     V
   Valid?
~~~
{: #overall-flow title="VTSS verifiation procedure"}

VTSS extends the syntax of a TSS scheme with a new function that supports share verification,
described below:

- VerifyShare(share): Output 1 if the share is valid and 0 otherwise.

The rest of this section describes how to construct a VTSS scheme.

## Construction

A TSS scheme is parameterzed by a prime-order group G that implements the abstraction described in {{dep-pog}}.
Using G, the RandomSplit, SplitAt, and Recover functions are implemented as follows.

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
    x = G.DeserializeScalar(share[0:Nscalar])
    y = G.DeserializeScalar(share[Nscalar:2*Nscalar])
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

Finally, VerifyShare is implemented as follows.

~~~~~
def Verify(share):
  x = G.DeserializeScalar(share[0:Nscalar])
  y = G.DeserializeScalar(share[Nscalar:2*Nscalar])
  commitment = share[2*Nscalar:]
  
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

TODO Security

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
