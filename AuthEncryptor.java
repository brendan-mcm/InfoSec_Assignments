/**********************************************************************************/
/* AuthEncryptor.java                                                             */
/* ------------------------------------------------------------------------------ */
/* author: bm18                                                                   */
/* date: 01MAR2022                                                                */
/* DESCRIPTION: Performs authenticated encryption of data.                        */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement authenticated encryption, ensuring:                       */
/*            (1) Confidentiality: the only way to recover encrypted data is to   */
/*                perform authenticated decryption with the same key and nonce    */
/*                used to encrypt the data.                                       */
/*            (2) Integrity: A party decrypting the data using the same key and   */
/*                nonce that were used to encrypt it can verify that the data has */
/*                not been modified since it was encrypted.                       */
/*                                                                                */
/**********************************************************************************/
public class AuthEncryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = StreamCipher.NONCE_SIZE_BYTES;

    // Instance variables.
    private byte[] msgKey; // saved symmetric key 
    private PRF macPRF; // PRF for MAC computation

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        
        msgKey = key;
        // MAC key generation
        byte[] macKey = new byte[KEY_SIZE_BYTES];
        PRGen macGen = new PRGen(msgKey); 
        for (int i = 0; i < KEY_SIZE_BYTES; i++) {
            macKey[i] = (byte) macGen.next(8);
        }

        // PRF = secure MAC via proof from lecture
        macPRF = new PRF(macKey);     
    }

    // Encrypts the contents of <in> so that its confidentiality and integrity are protected against those who do not
    //     know the key and nonce.
    // If <nonceIncluded> is true, then the nonce is included in plaintext with the output.
    // Returns a newly allocated byte[] containing the authenticated encryption of the input.
    public byte[] authEncrypt(byte[] in, byte[] nonce, boolean includeNonce) {
        assert(nonce.length == NONCE_SIZE_BYTES);

        StreamCipher mainStream = new StreamCipher(msgKey, nonce); // unique session key {message, nonce}
        
        byte[] cipher = new byte[in.length];
        mainStream.cryptBytes(in, 0, cipher, 0, in.length); // encrypt bytes and store into cipher

        // MAC part
        byte[] cipherNonce = new byte[cipher.length + nonce.length]; // concatenate cipher and nonce for MAC
        System.arraycopy(cipher, 0, cipherNonce, 0, cipher.length);
        System.arraycopy(nonce, 0, cipherNonce, cipher.length, nonce.length);
        
        byte[] mac = macPRF.eval(cipherNonce); // MAC depends on both message and nonce
        macPRF.update(nonce); // guarantees in-order messages

        // Final concatenation
        byte[] output;
        if (includeNonce) {
            output = new byte[cipher.length + mac.length + nonce.length];
            System.arraycopy(nonce, 0, output, (cipher.length + mac.length), nonce.length);
        } else {
            output = new byte[cipher.length + mac.length];
        }

        System.arraycopy(cipher, 0, output, 0, cipher.length); // first part is ciphertext
        System.arraycopy(mac, 0, output, cipher.length, mac.length); // second part is MAC

        return output;
    }
}
