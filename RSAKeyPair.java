import java.math.BigInteger;

/***
 * author: bm18 (MODIFIED)
 * This class represents a pair of RSA keys to be used for asymmetric encryption.
 * author: bm18 (modified)
 */
public class RSAKeyPair {
    private RSAKey publicKey;
    private RSAKey privateKey;

    private BigInteger p; // for use with getPrimes()
    private BigInteger q;

    final private BigInteger e = BigInteger.valueOf(65537); // constant e = 65537

    /***
     * Create an RSA key pair.
     *
     * @param rand PRGen that this class can use to get pseudorandom bits
     * @param numBits size in bits of each of the primes that will be used 
     */
    public RSAKeyPair(PRGen rand, int numBits) {
        
        // generate primes
        p = BigInteger.probablePrime(numBits, rand);
        q = BigInteger.probablePrime(numBits, rand);

        BigInteger one = BigInteger.valueOf(1);
        BigInteger n = p.multiply(q); // n = p * q
        BigInteger totient = (p.subtract(one)).multiply(q.subtract(one)); // phi(n) = (p-1)*(q-1)

        if (!(totient.gcd(e).equals(one)) || e.compareTo(totient) != -1) { // sanity check
          System.out.println("exponent e is not relatively prime to phi(n)");
          return;
        }
        
        BigInteger d = e.modInverse(totient);
        
        publicKey = new RSAKey(e, n);
        privateKey = new RSAKey(d, n);
    }

    /***
     * Get the public key from this keypair.
     *
     * @return public RSAKey corresponding to this pair
     */
    public RSAKey getPublicKey() {
        return publicKey;
    }

    /***
     * Get the private key from this keypair.
     *
     * @return private RSAKey corresponding to this pair
     */
    public RSAKey getPrivateKey() {
        return privateKey;
    }

    /***
     * Get an array containing the two primes that were used in this KeyPair's generation. In real life, this wouldn't
     * usually be necessary (we don't always keep track of the primes used for generation). Including this function here
     * is for grading purposes.
     *
     * @return two-element array of BigIntegers containing both of the primes used to generate this KeyPair
     */
    public BigInteger[] getPrimes() {
        BigInteger[] primes = new BigInteger[2];
        primes[0] = p;
        primes[1] = q;
        
        return primes;
    }
}
