import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/***
 * This provides a convenient wrapper for the hash function that you should use in your RSA-OAEP implementation.
 */
public class HashFunction {
    /***
     * Computes the SHA-256 hash of an input byte buffer. You should use this in your RSA-OAEP implementation.
     *
     * @param message data over which to compute the SHA-256 hash
     * @return SHA-256 hash output with given message as input
     */
    public static byte[] computeHash(byte[] message) {
        MessageDigest digest;
        try {
            // instantiate a SHA-256 hash digest
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // this is a fatal error and should never occur (since we know SHA-256 is in the standard cryptographic library)
            throw new RuntimeException(e);
        }

        // compute and return the hash value
        return digest.digest(message);
    }
}
