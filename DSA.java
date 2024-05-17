import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
public class DSA {
    private static Random random = new Random();
    public static BigInteger[] generateSafeDSAParameters(int bitLength, int iterations) {
        // Result array to store the generated parameters (p, q, alpha)
        BigInteger[] result = new BigInteger[3];
        // Generate a probable prime q of 160 bits
        BigInteger q = BigInteger.probablePrime(bitLength - 864, random);
        BigInteger p;
        // Generate a prime p of the form 2q + 1.
        do {
            p = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
            if (!p.isProbablePrime(iterations)) {
                q = BigInteger.probablePrime(bitLength - 1, random);
            }
        } while (!p.isProbablePrime(iterations));

        BigInteger alpha = findGenerator(p, q);
        if (alpha != null) {
            result[0] = p;
            result[1] = q;
            result[2] = alpha;
            return result;
        }
        return null; // No suitable parameters found
    }


    // Find a generator α with ord(α) = q
    private static BigInteger findGenerator(BigInteger p, BigInteger q) {
        BigInteger alpha = BigInteger.TWO;//initialize alpha =2

        while (alpha.compareTo(p) < 0) {
            if (alpha.modPow(q, p).equals(BigInteger.ONE))
            {
                return alpha; // alpha is a generator

            }
            alpha = alpha.add(BigInteger.ONE);//alpha ++
        }

        return null; // No generator found
    }

    // Choose a random integer d with 0 < d < q
    public static BigInteger chooseRandomInteger(BigInteger q) {
        Random random = new Random();
        // Generate a random integer between 1 and q-1
        BigInteger d = new BigInteger(q.bitLength(), random);
        // Ensure d is greater than 0 and less than q
        while (d.compareTo(BigInteger.ZERO) <= 0 || d.compareTo(q) >= 0) {
            d = new BigInteger(q.bitLength(), random);
        }
        return d;
    }

    // Function for square and multiply algorithm
    public static BigInteger squareAndMultiply(BigInteger base, BigInteger exponent, BigInteger modulo) {
        BigInteger result = BigInteger.ONE;
        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            //checks the least significant bit
            if (exponent.testBit(0)) {
                result = result.multiply(base).mod(modulo);
            }
            base = base.multiply(base).mod(modulo);
            //Right shift the exponent
            exponent = exponent.shiftRight(1);
        }
        return result;
    }

    // Generate keys function
    public static BigInteger[] generateKeys(BigInteger p, BigInteger q, BigInteger alpha) {
        BigInteger d = chooseRandomInteger(q);
        BigInteger beta = squareAndMultiply(alpha, d, p);
        return new BigInteger[]{d, beta};
    }


    private static final int[] K = {
            0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
    };

    public static BigInteger start_hash(int message) {
        // Convert number to byte array
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[3 - i] = (byte) (message >> (i * 8));
        }

        // Padding the message
        byte[] paddedMessage = padding_message(bytes);

        // Divide the padded message into 512-bit chunks
        byte[][] chunks = divideIntoChunks(paddedMessage);

        // Calculate SHA-1 hash for each chunk
        BigInteger hash = BigInteger.ZERO;
        for (byte[] chunk : chunks) {
            hash = hash.add(hash(chunk));
        }

        // Return the hash as a BigInteger
        return hash;
    }
    public static byte[] padding_message(byte[] message) {
        // append a '1' bit to the message
        byte[] padded = new byte[message.length + 1];
        for (int i = 0; i < message.length; i++) {
            padded[i] = message[i];
        }
        padded[message.length] = (byte) 0x80;

        // append '0' bits until padded.length % 512 == 448
        int zeroPadding = (448 - (padded.length * 8 % 512) + 512) % 512;
        byte[] zeroPadded = new byte[padded.length + zeroPadding / 8];
        for (int i = 0; i < padded.length; i++) {
            zeroPadded[i] = padded[i];
        }

        // append message length as a 64-bit big-endian integer
        long ml = message.length * 8;
        byte[] lengthBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            lengthBytes[7 - i] = (byte) ((ml >> (i * 8)) & 0xFF);
        }
        byte[] finalMessage = new byte[zeroPadded.length + 8];
        for (int i = 0; i < zeroPadded.length; i++) {
            finalMessage[i] = zeroPadded[i];
        }
        for (int i = 0; i < 8; i++) {
            finalMessage[zeroPadded.length + i] = lengthBytes[i];
        }

        return finalMessage;
    }

    private static byte[][] divideIntoChunks(byte[] paddedMessage) {
        int numOfChunks = paddedMessage.length / 64;   // 64bytes = 512 bits
        if (paddedMessage.length % 64 != 0) {
            numOfChunks++; // If the padded message doesn't evenly divide into chunks, add one more chunk
        }

        byte[][] chunks = new byte[numOfChunks][64];
        for (int i = 0; i < numOfChunks; i++) {
            for (int j = 0; j < 64; j++) {
                if (i * 64 + j < paddedMessage.length) {
                    chunks[i][j] = paddedMessage[i * 64 + j];
                } else {
                    // Pad with zeroes if the last chunk is incomplete
                    chunks[i][j] = 0;
                }
            }
        }
        return chunks;
    }

    public static BigInteger hash(byte[] message) {
        int[] h0 = {0x67452301};
        int[] h1 = {0xEFCDAB89};
        int[] h2 = {0x98BADCFE};
        int[] h3 = {0x10325476};
        int[] h4 = {0xC3D2E1F0};

        // process each 512-bit block
        for (int i = 0; i < message.length; i += 64) {
            int[] w = new int[80];
            for (int j = 0; j < 16; j++) {
                w[j] = ((message[i + j * 4] & 0xFF) ) |
                        ((message[i + j * 4 + 1] & 0xFF) ) |
                        ((message[i + j * 4 + 2] & 0xFF) ) |
                        (message[i + j * 4 + 3] & 0xFF);
            }
            for (int j = 16; j < 80; j++) {
                w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            }

            int A = h0[0];
            int B = h1[0];
            int C = h2[0];
            int D = h3[0];
            int E = h4[0];

            for (int j = 0; j < 80; j++) {
                int f, k;
                if (j < 20) {
                    f = (B & C) | ((~B) & D);
                    k = K[0];
                } else if (j < 40) {
                    f = B ^ C ^ D;
                    k = K[1];
                } else if (j < 60) {
                    f = (B & C) | (B & D) | (C & D);
                    k = K[2];
                } else {
                    f = B ^ C ^ D;
                    k = K[3];
                }

                int tempP = E + f + (leftRotate(A, 5)) + w[j] + k;
                E = D;
                D = C;
                C = leftRotate(B, 30);
                B = A;
                A = tempP;
            }

            h0[0] += A;
            h1[0] += B;
            h2[0] += C;
            h3[0] += D;
            h4[0] += E;
        }
        // Combine the hash values to a single 160-bit string
        String hashHex = Integer.toHexString(h0[0]) +
                Integer.toHexString(h1[0]) +
                Integer.toHexString(h2[0]) +
                Integer.toHexString(h3[0]) +
                Integer.toHexString(h4[0]);


        // Pad the hexadecimal string with leading zeros if necessary
        while (hashHex.length() < 40) {
            hashHex = "0" + hashHex;
        }
        System.out.println("hashed message in hex: " + hashHex);


        // Convert the hexadecimal string to a BigInteger
        BigInteger final_result = BigInteger.valueOf(h0[0] & 0xFFFFFFFFL).shiftLeft(32)
                .or(BigInteger.valueOf(h1[0] & 0xFFFFFFFFL));
        return final_result;
    }

    private static int leftRotate(int value, int count) {
        return (value << count) | (value >>> (32 - count));
    }


    public static BigInteger[] generateDSASignature(BigInteger p, BigInteger q, BigInteger alpha, BigInteger d, BigInteger hashedMessage) {
        Random random = new Random();

        // Step 1: Choose an integer as random ephemeral key kE with 0 < kE < q
        BigInteger kE;
        do {
            kE = new BigInteger(q.bitLength(), random);
        } while (kE.compareTo(BigInteger.ZERO) <= 0 || kE.compareTo(q) >= 0);

        // Step 2: Compute r ≡ (α^kE mod p) mod q using square and multiply
        BigInteger r = squareAndMultiply(alpha, kE, p).mod(q);

        // Calculate kE^−1 using extended Euclidean algorithm
        BigInteger[] euclideanResult = extendedEuclidean(kE, q);
        BigInteger kInverse = euclideanResult[1];
        if (kInverse.compareTo(BigInteger.ZERO) < 0) {
            // Ensure kE^−1 is positive
            kInverse = kInverse.add(q);
        }

        // Step 3: Compute s ≡ (hashedMessage + d * r) * kE^−1 mod q
        BigInteger s = (hashedMessage.add(d.multiply(r))).multiply(kInverse).mod(q);

        return new BigInteger[]{r, s, kE, kInverse};
    }


    // Function for extended Euclidean algorithm
    public static BigInteger[] extendedEuclidean(BigInteger a, BigInteger b) {
        BigInteger t = BigInteger.ZERO;
        BigInteger s = BigInteger.ONE;
        BigInteger last_t = BigInteger.ONE;
        BigInteger last_s = BigInteger.ZERO;

        while (!b.equals(BigInteger.ZERO)) {
            BigInteger[] quotientAndRemainder = a.divideAndRemainder(b);
            BigInteger quotient = quotientAndRemainder[0];
            a = b;
            b = quotientAndRemainder[1];

            BigInteger temp_t = t;
            t = last_t.subtract(quotient.multiply(t));
            last_t = temp_t;

            BigInteger temp_s = s;
            s = last_s.subtract(quotient.multiply(s));
            last_s = temp_s;
        }

        return new BigInteger[]{a, last_t, last_s};
    }


    public static boolean verifyDSASignature(BigInteger p, BigInteger q, BigInteger alpha, BigInteger beta, BigInteger hashedMessage, BigInteger r, BigInteger s) {
        // Step 1: Compute auxiliary value w ≡ s^-1 mod q.
        BigInteger w = s.modInverse(q);
        System.out.println("w: " + w);

        // Step 2: Compute auxiliary value u1 ≡ (hashedMessage * w) mod q.
        BigInteger u1 = hashedMessage.multiply(w).mod(q);
        System.out.println("u1: " + u1);

        // Step 3: Compute auxiliary value u2 ≡ (r * w) mod q.
        BigInteger u2 = r.multiply(w).mod(q);
        System.out.println("u2: " + u2);

        // Step 4: Compute v ≡ ((alpha^u1 * beta^u2) mod p) mod q.
        BigInteger v1 = alpha.modPow(u1, p);
        BigInteger v2 = beta.modPow(u2, p);
        BigInteger v = (v1.multiply(v2)).mod(p).mod(q);
        System.out.println("v: " + v);

        //r=BigInteger.valueOf(10);
        // Step 5: Check if v equals r
        return v.equals(r);
    }


    public static void main(String[] args) {



        Scanner scanner = new Scanner(System.in);

        // Get user input for the message
        System.out.print("Enter an integer message: ");
        int message = scanner.nextInt();

        // Hash the message using start_hash
        BigInteger hashedMessage = start_hash(message);
        System.out.println("Hashed message: " + hashedMessage);
        int bitLength = 1024; // Bit length for p
        int iterations = 100; // Number of iterations for prime checking


        BigInteger[] params = generateSafeDSAParameters(bitLength, iterations);

        if (params != null) {
            System.out.println("p: " + params[0]);
            System.out.println("q: " + params[1]);
            System.out.println("α: " + params[2]);
            BigInteger[] keys = generateKeys(params[0], params[1], params[2]);
            System.out.println("d (private key): " + keys[0]);
            System.out.println("β (public key): " + keys[1]);
            BigInteger[] signature =generateDSASignature(params[0], params[1], params[2], keys[0], hashedMessage);
            BigInteger r = signature[0];
            BigInteger s = signature[1];
            BigInteger kE = signature[2];
            BigInteger kInverse = signature[3];

            System.out.println("r: " + r);
            System.out.println("s: " + s);
            System.out.println("kE: " + kE);
            System.out.println("kInverse: " + kInverse);

            if (verifyDSASignature(params[0], params[1], params[2], keys[1], hashedMessage, r, s)) {
                System.out.println("Valid Signature");
            } else {
                System.out.println("Invalid Signature");
            }
        } else {
            System.out.println("Failed to generate DSA parameters.");
   }

 }
}
