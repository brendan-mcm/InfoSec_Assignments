import java.util.Arrays;

/**********************************************************************************/
/* AuthDecrytor.java                                                              */
/* author: bm18                                                                   */
/* date: 01MAR2022                                                                */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated decryption of data encrypted using         */
/*              AuthEncryptor.java.                                               */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Decrypt data encrypted by your implementation of AuthEncryptor.java */
/*            if provided with the appropriate key and nonce.  If the data has    */
/*            been tampered with, return null.                                    */
/*                                                                                */
/**********************************************************************************/
public class AuthDecryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;

    private byte[] msgKey; // saved symmetric key
    private PRF macPRF; // PRF for MAC computation

    public AuthDecryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;

        // Same setup as AuthEncryptor
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

    /* Helper function to check integrity, returns true if integrity is guaranteed, false if not */
    private boolean checkIntegrity (byte[] cipher, byte[] mac, byte[] nonce){

        byte[] cipherNonce = new byte[cipher.length + nonce.length]; // concatenate cipher and nonce for MAC
        System.arraycopy(cipher, 0, cipherNonce, 0, cipher.length);
        System.arraycopy(nonce, 0, cipherNonce, cipher.length, nonce.length);

        byte[] genMac = macPRF.eval(cipherNonce); // MAC depends on both message and nonce

        if (!Arrays.equals(mac, genMac))
            return false; // cannot guarantee integrity
        
        macPRF.update(nonce); // update for in-order messaging after equality
        return true;
    }

    /* Helper function that checks integrity and returns plaintext or null if integrity not guaranteed */
    private byte[] checkDecryptBytes (byte[] cipher, byte[] mac, byte[] nonce) {

        // Check before decryption
        if (!checkIntegrity(cipher, mac, nonce))
            return null; // failed integrity check

        StreamCipher mainStream = new StreamCipher(msgKey, nonce); // unique session key
        byte[] decrypted = new byte[cipher.length]; // decrypt and return
        mainStream.cryptBytes(cipher, 0, decrypted, 0, cipher.length);
        
        return decrypted;
    }


    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce has been included in <in>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in) {
        // (includeNonce = true)
        
        // Create and separate out message, MAC, nonce
        byte[] nonce = new byte[NONCE_SIZE_BYTES]; 
        byte[] mac = new byte[PRF.OUTPUT_SIZE_BYTES];
        byte[] cipher = new byte[in.length - nonce.length - mac.length];

        System.arraycopy(in, cipher.length + mac.length, nonce, 0, nonce.length);
        System.arraycopy(in, cipher.length, mac, 0, mac.length);
        System.arraycopy(in, 0, cipher, 0, cipher.length);

        return checkDecryptBytes(cipher, mac, nonce);
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce used to encrypt the data is provided in <nonce>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in, byte[] nonce) {
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;
       
        // separate out ciphertext and MAC
        byte[] mac = new byte[PRF.OUTPUT_SIZE_BYTES];
        byte[] cipher = new byte[in.length - mac.length];

        System.arraycopy(in, cipher.length, mac, 0, mac.length);
        System.arraycopy(in, 0, cipher, 0, cipher.length);

        return checkDecryptBytes(cipher, mac, nonce);
    }
}
