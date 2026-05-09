import java.lang.reflect.Array;
import java.math.BigInteger;
/***
 * author: bm18 (MODIFIED)
 * This class represents a single RSA key that can perform the RSA encryption and signing algorithms discussed in
 * class. Note that some of the public methods would normally not be part of a production API, but we leave them
 * public for the sake of grading.
 */
public class RSAKey {
    private BigInteger exponent;
    private BigInteger modulus;

    private final int k0 = 128; // fixed random nonce length (bits)
    private final int k1 = 128; // fixed padding length (bits)

    private final byte FLAG = (byte) 0xff; // padding signal

    /***
     * Constructor. Create an RSA key with the given exponent and modulus.
     * 
     * @param theExponent exponent to use for this key's RSA math
     * @param theModulus modulus to use for this key's RSA math
     */
    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;
    }

    /***
     * Get the exponent used for this key's encryption/decryption.
     *
     * @return BigInteger containing this key's exponent
     */
    public BigInteger getExponent() {
        return exponent;
    }

    /***
     * Get the modulus used for this key's encryption/decryption.
     *
     * @return BigInteger containing this key's modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /***
     * Pad plaintext input if it is too short for OAEP. Do not call this from {@link #encodeOaep(byte[], PRGen)}.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input plaintext to pad
     * @return padded plaintext of appropriate length for OAEP
     */
    public byte[] addPadding(byte[] input) {
        // The padding called before OAEP. Should output size of (n/8 - 1 - k0/8 - k1/8) where n = big length . 
        byte[] padded = new byte[ (modulus.bitLength()/8) - 1 - (k0/8) - (k1/8)]; // 8 bits / byte, default initialized to 0
        
        System.arraycopy(input, 0, padded, 0, input.length); // leaves last numPadBytes untouched, i.e 0
        Array.setByte(padded, input.length, FLAG); // first byte of padding is flag

        return padded;
    }

    /***
     * Remove padding applied by {@link #addPadding(byte[])} method. Do not call this from {@link #decodeOaep(byte[])}.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input padded plaintext from which we extract plaintext
     * @return plaintext in {@code input} without padding
     */
    public byte[] removePadding(byte[] input) {
    
        int startPadding = 0;
        for (int i = (input.length - 1); i >= 0; i--) { // start from end, minimum one byte of padding
            if (input[i] == FLAG) {
                startPadding = i;
                break;
            }
        }

        byte[] unpadded = new byte[startPadding]; // copy original input into new array
        System.arraycopy(input, 0, unpadded, 0, unpadded.length);

        return unpadded;
    }

    /***
     * Encode a plaintext input with OAEP method. May require basic padding before calling. Do not call
     * {@link #addPadding(byte[])} from this method.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input plaintext to encode
     * @param prgen pseudo-random generator to use in encoding algorithm
     * @return OAEP encoded plaintext
     */
    public byte[] encodeOaep(byte[] input, PRGen prgen) {

        int sizeR = k0 / 8; // fixed 16 bytes, generate r w/ given PRGen
        byte[] r = new byte[sizeR];
        for (int i = 0; i < sizeR; i++) {
            Array.set(r, i, (byte)prgen.next(8));
        }

        byte[] r_ext = new byte[r.length + 16]; // zero extend r to fit PRGen requirement
        System.arraycopy(r, 0, r_ext, 0, r.length);
        PRGen g = new PRGen(r_ext);

        int sizeX = input.length;
        byte[] x = new byte[sizeX + (k1 / 8)]; // second round of 0 padding, initialized to 0
        for (int i = 0; i < sizeX; i++) {
            Array.set(x, i, (byte)(input[i] ^ (byte)g.next(8)) ); // XOR w/ PRGen G
        }

        // zero padding part of fixed 16 bytes
        for (int i = sizeX; i < x.length; i++) {
            Array.set(x, i, (byte)g.next(8)); // (1 | 0) XOR 0 is just original value
        }

        byte[] hashed = HashFunction.computeHash(x); // hash gives 32 byte output
       
        byte[] y = new byte[sizeR];
        for (int i = 0; i < sizeR; i++) { // end up limited to using 16 of the bytes due to size of r
            Array.set(y, i, (byte)(hashed[i] ^ r[i]));
        }

        byte[] xy = new byte[x.length + y.length];
        System.arraycopy(x, 0, xy, 0, x.length); // copy x into leftmost block
        System.arraycopy(y, 0, xy, x.length, y.length); // copy y into rightmost block
        
        return xy;
    }

    /***
     * Decode an OAEP encoded message back into its plaintext representation. May require padding removal after calling.
     * Do not call {@link #removePadding(byte[])} from this method.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input OEAP encoded message
     * @return decoded plaintext message
     */
    public byte[] decodeOaep(byte[] input) {
        // First separate out X, Y
        byte[] y = new byte[k0/8]; // Fixed 16 bytes
        byte[] x = new byte[input.length - y.length];
        System.arraycopy(input, 0, x, 0, x.length); // take x from leftmost block
        System.arraycopy(input, x.length, y, 0, y.length); // take y from rightmost block

        byte[] hashed = HashFunction.computeHash(x); // hash gives 32 byte output
        
        // recover r
        byte[] r = new byte[y.length];
        for (int i = 0; i < y.length; i++) {
            Array.set(r, i, (byte)(hashed[i] ^ y[i]));
        }
        
        // seed G w/ zero extended r and recover x
        byte[] r_ext = new byte[y.length + 16]; // total input
        System.arraycopy(r, 0, r_ext, 0, y.length);
        PRGen g = new PRGen(r_ext);

        for (int i = 0; i < x.length; i++) {
            Array.set(x, i, (byte) (x[i] ^ (byte)g.next(8))); // symmetric XOR to recover m w/ padding
        }
        
        byte[] message = new byte[x.length - (k1/8)];
        System.arraycopy(x, 0, message, 0, message.length); // remove k1 padding of 0's

        return message;
    }

    /***
     * Get the largest N such that any plaintext of size N bytes can be encrypted with this key and padding/encoding.
     *
     * @return upper bound of plaintext length applicable for this key
     */
    public int maxPlaintextLength() {
        int maxBytes = (modulus.bitLength() / 8) - (k0/8) - (k1/8) - 1 - 1; // one padding constant, and - 1 extra
        return maxBytes;
    }

    /***
     * Encrypt the given plaintext message using RSA algorithm with this key.
     *
     * @param plaintext message to encrypt
     * @param prgen pseudorandom generator to be used for encoding/encryption
     * @return ciphertext result of RSA encryption on this plaintext/key
     * @throws Exception
     */
    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null) throw new NullPointerException();
        if (plaintext.length > maxPlaintextLength()) return null;
   
        byte[] padM = addPadding(plaintext); // guaranteed to fit size constraint
        byte[] oaepM = encodeOaep(padM, prgen);
       
        BigInteger message = HW2Util.bytesToBigInteger(oaepM);
        BigInteger enc = message.modPow(exponent, modulus); // m^e (mod n)
        byte[] cipher = HW2Util.bigIntegerToBytes(enc, modulus.bitLength()/8);

        return cipher;
    }

    /***
     * Decrypt the given ciphertext message using RSA algorithm with this key. Effectively the inverse of our
     * {@link #encrypt(byte[], PRGen)} method.
     *
     * @param ciphertext encrypted message to decrypt
     * @return plaintext message
     */
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null) throw new NullPointerException();

        BigInteger cipher = HW2Util.bytesToBigInteger(ciphertext);
        BigInteger unenc = cipher.modPow(exponent, modulus); // c^d (mod n)
        
        byte[] oaepM = decodeOaep(HW2Util.bigIntegerToBytes(unenc, (modulus.bitLength()/8) - 1));
        byte[] message = removePadding(oaepM);

        return message;
    }

    /***
     * Create a digital signature on {@code message}. The signature need not contain the contents of {@code message}; we
     * will assume that a party who wants to verify the signature will already know with which message this signature is
     * meant to be associated.
     *
     * @param message message to sign
     * @param prgen pseudorandom generator used for signing
     * @return RSA signature of the message using this key
     */
    public byte[] sign(byte[] message, PRGen prgen) {
        if (message == null) throw new NullPointerException();

        byte[] hash = HashFunction.computeHash(message);
        BigInteger hashed = HW2Util.bytesToBigInteger(hash);
        BigInteger sign = hashed.modPow(exponent, modulus); // m ^ d (mod n)
        byte[] signed = HW2Util.bigIntegerToBytes(sign, modulus.bitLength() / 8); // conversion back
        
        return signed;
    }

    /***
     * Verify a digital signature against this key. Returns true if and only if {@code signature} is a valid RSA
     * signature on {@code message}; returns false otherwise. A "valid" RSA signature is one that was created by calling
     * {@link #sign(byte[], PRGen)} with the same message on the other RSAKey that belongs to the same RSAKeyPair as
     * this RSAKey object.
     *
     * @param message message that has been signed
     * @param signature signature to validate against this key
     * @return true iff this RSAKey object's counterpart in a keypair signed the given message and produced the given
     * signature
     */
    public boolean verifySignature(byte[] message, byte[] signature) {
        if ((message == null) || (signature == null)) throw new NullPointerException();

        byte[] hash = HashFunction.computeHash(message); // hash message
        BigInteger hashed = HW2Util.bytesToBigInteger(hash);

        BigInteger signatureOther = HW2Util.bytesToBigInteger(signature);
        BigInteger sigRes = signatureOther.modPow(exponent, modulus); // S ^ e (mod n)
        
        return hashed.equals(sigRes); // compare signatures
    }
}
