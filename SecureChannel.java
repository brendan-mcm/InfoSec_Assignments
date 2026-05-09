import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* 
    author: bm18
    date: 01MAR2022
*/

public class SecureChannel extends InsecureChannel {
    // This is just like an InsecureChannel, except that it provides 
    //    authenticated encryption for the messages that pass
    //    over the channel.   It also guarantees that messages are delivered 
    //    on the receiving end in the same order they were sent (returning
    //    null otherwise).  Also, when the channel is first set up,
    //    the client authenticates the server's identity, and the necessary
    //    steps are taken to detect any man-in-the-middle (and to close the
    //    connection if a MITM is detected).
    //
    // The code provided here is not secure --- all it does is pass through
    //    calls to the underlying InsecureChannel.

    private AuthEncryptor encryptor; // for symmetric encryption
    private AuthDecryptor decryptor;
    
    private PRGen rand; // for nonce generation
    private boolean active; // indicates if connection is closed

    public void close () throws IOException {
        
        System.out.println("Closing connection...");

        // clear all values
        encryptor = null;
        decryptor = null;
        rand = null;
        active = false;

        super.close();
    }

    public SecureChannel(InputStream inStr, OutputStream outStr,
                         PRGen rand, boolean iAmServer,
                         RSAKey serverKey) throws IOException {
        // if iAmServer==false, then serverKey is the server's *public* key
        // if iAmServer==true, then serverKey is the server's *private* key

        super(inStr, outStr);
        this.rand = rand; // for nonce generation

        KeyExchange swap = new KeyExchange(rand, iAmServer); // for DHKE
        byte[] digest = swap.prepareOutMessage();

        super.sendMessage(digest); // first send, then receive
        byte[] responseDigest = super.receiveMessage();

        byte[] symmKey = swap.processInMessage(responseDigest); // new shared key (UNAUTHENTICATED)

        // Separate keys for Alice->Bob and Bob->Alice
        PRGen symmPRGen = new PRGen(symmKey);
        byte[] symmKeyOne = new byte[32];
        byte[] symmKeyTwo = new byte[32];
        for (int i = 0; i < symmKeyOne.length; i++) {
            symmKeyOne[i] = (byte) symmPRGen.next(8);
            symmKeyTwo[i] = (byte) symmPRGen.next(8);
        }

        if (iAmServer) { // SERVER
            encryptor = new AuthEncryptor(symmKeyOne);
            decryptor = new AuthDecryptor(symmKeyTwo);
            active = true; // can send along communication, encryptor / decryptors initialized

            // Server signs shared symmetric key w/ private key and sends signature via new secure channel
            byte[] serverSignature = serverKey.sign(symmKey, rand);
            sendMessage(serverSignature);

        } else { // CLIENT
            encryptor = new AuthEncryptor(symmKeyTwo);
            decryptor = new AuthDecryptor(symmKeyOne);
            active = true; // can send along communication, encryptor / decryptors initialized

            byte[] signatureServer = receiveMessage();
            
            // RSA verfication of shared symmetric key
            if (serverKey.verifySignature(symmKey, signatureServer)) {
                System.out.println("Authenticated.");
            } else {
                System.out.println("Server identity could not be verified.");
                close();
            }
        }  

    }

    public void sendMessage(byte[] message) throws IOException {
        if (!active) return;
        
        // generate nonce
        byte[] nonce = new byte[8];
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) (rand.next(8));
        }

        byte[] cipher = encryptor.authEncrypt(message, nonce, true); // true makes it simpler
        super.sendMessage(cipher);
    }

    public byte[] receiveMessage() throws IOException {
        if (!active) return null;

        byte[] cipher = super.receiveMessage(); // encrypted message || MAC || nonce
        byte[] decrypted = decryptor.authDecrypt(cipher);
        
        if (decrypted == null) {
            System.out.println("Message integrity could not be verified.");
            close();
        }

        return decrypted;
    }
}
