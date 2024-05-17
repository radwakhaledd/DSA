# DSA
implementation of DSA  java code
Digital Signature Algorithm (DSA) Implementation in Java
Overview
This Java program implements the Digital Signature Algorithm (DSA), which is a Federal Information Processing Standard for digital signatures. The program covers the generation of DSA parameters, key generation, message hashing, signature generation, and signature verification.

Features
Safe DSA Parameters Generation: Generates safe primes 
𝑝
p and 
𝑞
q and a generator 
𝛼
α.
Key Generation: Generates a private key 
𝑑
d and a public key 
𝛽
β.
Message Hashing: Hashes a message using a simplified SHA-1 algorithm.
Signature Generation: Signs a hashed message to produce 
𝑟
r and 
𝑠
s values.
Signature Verification: Verifies the generated signature against the original message and the public key.
How to Use
Prerequisites
Java Development Kit (JDK) installed on your machine.
Basic understanding of Java programming and the command line.
Input
The program prompts the user to enter an integer message which will be hashed and signed.
Output
The program outputs the generated DSA parameters (
𝑝
p, 
𝑞
q, 
𝛼
α).
It shows the private key (
𝑑
d) and the public key (
𝛽
β).
It displays the generated signature values (
𝑟
r and 
𝑠
s).
It verifies and outputs whether the signature is valid or invalid.
Code Structure
Main Class: DSA
generateSafeDSAParameters(int bitLength, int iterations): Generates safe DSA parameters.
findGenerator(BigInteger p, BigInteger q): Finds a suitable generator 
𝛼
α.
chooseRandomInteger(BigInteger q): Chooses a random integer 
𝑑
d for key generation.
squareAndMultiply(BigInteger base, BigInteger exponent, BigInteger modulo): Performs exponentiation using the square-and-multiply algorithm.
generateKeys(BigInteger p, BigInteger q, BigInteger alpha): Generates DSA keys.
start_hash(int message): Hashes the message.
padding_message(byte[] message): Pads the message to fit into 512-bit chunks.
divideIntoChunks(byte[] paddedMessage): Divides the padded message into 512-bit chunks.
hash(byte[] message): Computes the SHA-1 hash of the message.
leftRotate(int value, int count): Performs left rotation on an integer.
generateDSASignature(BigInteger p, BigInteger q, BigInteger alpha, BigInteger d, BigInteger hashedMessage): Generates the DSA signature.
extendedEuclidean(BigInteger a, BigInteger b): Computes the extended Euclidean algorithm.
verifyDSASignature(BigInteger p, BigInteger q, BigInteger alpha, BigInteger beta, BigInteger hashedMessage, BigInteger r, BigInteger s): Verifies the DSA signature.
Notes
This implementation is for educational purposes and simplifies certain aspects of the DSA and SHA-1 algorithms.
For production use, consider using well-established cryptographic libraries.
License
This project is licensed under the MIT License - see the LICENSE file for details.
