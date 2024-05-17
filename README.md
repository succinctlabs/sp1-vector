# SP1 Vector X

Primitives will contain the libraries for types as well as common functions used in verification which include:

1. Verifying signatures.
2. Decoding the header.
3. Constructing and verifyingthe authority set hash.
4. How expensive would it be to do hashing inside of the program?

## Early Benchmarking on the Performance
1. Let's try hashing 35K bytes with Blake2B